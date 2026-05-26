import unittest
from unittest.mock import MagicMock, patch

from modules.diagnostics import DiagnosticsCollector
from modules.neo4j_data import Neo4jData

class TestRecordEscalationBatchUnit(unittest.TestCase):

    def test_record_silently_bails_when_domain_uninitialized(self):
        dc = DiagnosticsCollector()
        dc.record_escalation_batch("DOMAIN.X", 0, 250, 1234.0, 12)
        self.assertEqual(dc.escalation_batches, {})

    def test_success_entry_has_no_success_key(self):
        dc = DiagnosticsCollector()
        dc.escalation_batches["DOMAIN.X"] = {"batches": []}
        dc.record_escalation_batch("DOMAIN.X", 3, 250, 49321.7, 12)
        entry = dc.escalation_batches["DOMAIN.X"]["batches"][0]
        self.assertEqual(entry, {
            "batch_num": 3,
            "size": 250,
            "duration_ms": 49321.7,
            "paths_found": 12,
        })
        self.assertNotIn("success", entry)
        self.assertNotIn("error", entry)

    def test_failed_entry_records_success_false_and_error(self):
        dc = DiagnosticsCollector()
        dc.escalation_batches["DOMAIN.X"] = {"batches": []}
        dc.record_escalation_batch("DOMAIN.X", 5, 250, 0, 0,
                                   success=False, error=RuntimeError("conn dropped"))
        entry = dc.escalation_batches["DOMAIN.X"]["batches"][0]
        self.assertFalse(entry["success"])
        self.assertEqual(entry["error"], "conn dropped")

    def test_duration_ms_rounded_to_one_decimal(self):
        dc = DiagnosticsCollector()
        dc.escalation_batches["DOMAIN.X"] = {"batches": []}
        dc.record_escalation_batch("DOMAIN.X", 0, 250, 1234.567, 0)
        self.assertEqual(dc.escalation_batches["DOMAIN.X"]["batches"][0]["duration_ms"], 1234.6)

    def test_two_domains_preserved(self):
        dc = DiagnosticsCollector()
        dc.escalation_batches["A"] = {"batches": []}
        dc.escalation_batches["B"] = {"batches": []}
        dc.record_escalation_batch("A", 0, 250, 100, 5)
        dc.record_escalation_batch("B", 0, 200, 50, 1)
        dc.record_escalation_batch("A", 1, 41, 30, 0)
        self.assertEqual(len(dc.escalation_batches["A"]["batches"]), 2)
        self.assertEqual(len(dc.escalation_batches["B"]["batches"]), 1)
        self.assertEqual([b["batch_num"] for b in dc.escalation_batches["A"]["batches"]], [0, 1])

    def test_to_dict_exposes_escalation_batches(self):
        dc = DiagnosticsCollector()
        dc.escalation_batches["A"] = {
            "mode": "parallel", "batch_size": 250, "total_batches": 2,
            "max_workers": 4, "batches": [],
        }
        dc.record_escalation_batch("A", 0, 250, 1000, 7)
        result = dc.to_dict()
        self.assertIn("escalation_batches", result)
        self.assertEqual(result["escalation_batches"]["A"]["mode"], "parallel")
        self.assertEqual(len(result["escalation_batches"]["A"]["batches"]), 1)

class TestParallelBatchFailureSurfaces(unittest.TestCase):

    def test_query_exception_records_success_false_per_batch_and_errors(self):
        conn = MagicMock()
        diag = DiagnosticsCollector()
        nd = Neo4jData(conn, domain_filter="A.LOCAL", diagnostics=diag)

        entities = [f"S-1-5-21-1-{i}" for i in range(1000)]

        with patch.object(nd, "_find_escalation_paths_v2",
                          side_effect=RuntimeError("simulated query failure")):
            nd._batch_process_v2(entities)

        eb = diag.escalation_batches.get("A.LOCAL")
        self.assertIsNotNone(eb)
        self.assertEqual(eb["mode"], "parallel")
        self.assertEqual(len(eb["batches"]), eb["total_batches"])
        for entry in eb["batches"]:
            self.assertFalse(entry.get("success", True))
            self.assertEqual(entry["paths_found"], 0)
            self.assertIn("simulated query failure", entry.get("error", ""))

        self.assertEqual(len(diag.errors), eb["total_batches"])
        for err in diag.errors:
            self.assertTrue(err["source"].startswith("escalation_batch_"))
            self.assertIn("simulated query failure", err["error"])
            self.assertEqual(err["domain"], "A.LOCAL")

class TestQuerySwallowSurfaces(unittest.TestCase):
    """Failures raised by conn.query() inside _find_escalation_paths_v2 must
    surface through escalation_batches and errors. Patches the underlying
    conn (not _find_escalation_paths_v2 itself), so the inner try/except
    swallow path is actually exercised."""

    def test_parallel_query_failure_records_per_batch_and_errors(self):
        conn = MagicMock()
        thread_conn = MagicMock()
        thread_conn.query.side_effect = RuntimeError("simulated query failure")
        conn.get_connection_for_thread.return_value = thread_conn

        diag = DiagnosticsCollector()
        nd = Neo4jData(conn, domain_filter="A.LOCAL", diagnostics=diag)

        with patch.object(nd, "get_all_relationships", return_value="A|B|C"):
            entities = [f"S-1-5-21-1-{i}" for i in range(1000)]
            nd._batch_process_v2(entities)

        eb = diag.escalation_batches.get("A.LOCAL")
        self.assertEqual(eb["mode"], "parallel")
        failed = [b for b in eb["batches"] if not b.get("success", True)]
        self.assertEqual(len(failed), eb["total_batches"])

        self.assertEqual(len(diag.errors), eb["total_batches"])
        for err in diag.errors:
            self.assertIn("simulated query failure", err["error"])
            self.assertEqual(err["domain"], "A.LOCAL")

    def test_sequential_query_failure_records_failed_batch(self):
        conn = MagicMock()
        conn.query.side_effect = RuntimeError("simulated query failure")

        diag = DiagnosticsCollector()
        nd = Neo4jData(conn, domain_filter="A.LOCAL", diagnostics=diag)

        with patch.object(nd, "get_all_relationships", return_value="A|B|C"):
            entities = [f"S-1-5-21-1-{i}" for i in range(100)]
            nd._batch_process_v2(entities)

        eb = diag.escalation_batches.get("A.LOCAL")
        self.assertEqual(eb["mode"], "sequential")
        self.assertEqual(eb["total_batches"], 1)
        failed = [b for b in eb["batches"] if not b.get("success", True)]
        self.assertEqual(len(failed), 1)
        self.assertEqual(len(diag.errors), 1)
        self.assertIn("simulated query failure", diag.errors[0]["error"])
        self.assertEqual(diag.errors[0]["domain"], "A.LOCAL")
