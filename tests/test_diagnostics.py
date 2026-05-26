import unittest
import json
import os
import tempfile
from unittest.mock import patch
from modules.diagnostics import DiagnosticsCollector, compute_audit_mode
from modules.neo4j_connection import InstrumentedConnection

class TestRecordQuery(unittest.TestCase):

    def test_cached_query(self):
        dc = DiagnosticsCollector()
        dc.record_query(name="cached_q", duration_ms=1, result_count=10, cached=True)
        self.assertTrue(dc.queries[0]["cached"])

    def test_batch_fields_included(self):
        dc = DiagnosticsCollector()
        dc.record_query(name="batch", duration_ms=200, result_count=100,
                        batch_count=5, cache_hits=20, cache_misses=80)
        q = dc.queries[0]
        self.assertEqual(q["batch_count"], 5)
        self.assertEqual(q["cache_hits"], 20)
        self.assertEqual(q["cache_misses"], 80)

    def test_optional_fields_omitted_when_none(self):
        dc = DiagnosticsCollector()
        dc.record_query(name="simple", duration_ms=10, result_count=5)
        q = dc.queries[0]
        self.assertNotIn("batch_count", q)
        self.assertNotIn("cache_hits", q)
        self.assertNotIn("cache_misses", q)

class TestInstrumentedConnectionFailures(unittest.TestCase):

    def test_raised_query_records_failure_and_reraises(self):
        class RaisingConnection:
            def query(self, query, parameters=None, db=None):
                raise RuntimeError("driver exploded")

        dc = DiagnosticsCollector()
        conn = InstrumentedConnection(RaisingConnection(), dc)

        with self.assertRaisesRegex(RuntimeError, "driver exploded"):
            conn.query("MATCH (n) RETURN n", name="raised_q")

        self.assertEqual(len(dc.queries), 1)
        entry = dc.queries[0]
        self.assertEqual(entry["name"], "raised_q")
        self.assertEqual(entry["result_count"], 0)
        self.assertEqual(entry["success"], False)

class TestRecordCheck(unittest.TestCase):

    def _record_basic(self, dc, **overrides):
        defaults = dict(
            name="TestCheck", risk_level="High", category="Test",
            entity_type="computer", duration_ms=50.3,
            entities_input=100, entities_after_filter=90,
            filtered_breakdown={"no_sid": 0, "disabled": 10, "domain_controller": 0, "wrong_entity_type": 0},
            findings_count=5,
        )
        defaults.update(overrides)
        dc.record_check(**defaults)

    def test_basic_check(self):
        dc = DiagnosticsCollector()
        self._record_basic(dc)
        self.assertEqual(len(dc.checks), 1)
        c = dc.checks[0]
        self.assertEqual(c["name"], "TestCheck")
        self.assertEqual(c["findings_count"], 5)
        self.assertEqual(c["duration_ms"], 50.3)
        self.assertEqual(c["entities_input"], 100)

    def test_finding_sids_included(self):
        dc = DiagnosticsCollector()
        self._record_basic(dc, finding_sids=["S-1-5-21-1", "S-1-5-21-2"])
        self.assertEqual(dc.checks[0]["finding_sids"], ["S-1-5-21-1", "S-1-5-21-2"])

    def test_unique_paths_included(self):
        dc = DiagnosticsCollector()
        self._record_basic(dc, unique_paths=5)
        self.assertEqual(dc.checks[0]["unique_paths"], 5)

    def test_optional_fields_omitted_when_none(self):
        dc = DiagnosticsCollector()
        self._record_basic(dc)
        self.assertNotIn("finding_sids", dc.checks[0])
        self.assertNotIn("unique_paths", dc.checks[0])

    def test_duration_rounded(self):
        dc = DiagnosticsCollector()
        self._record_basic(dc, duration_ms=123.456)
        self.assertEqual(dc.checks[0]["duration_ms"], 123.5)

class TestRecordError(unittest.TestCase):

    def test_error_converted_to_string(self):
        dc = DiagnosticsCollector()
        dc.record_error("src", Exception(42))
        self.assertEqual(dc.errors[0]["error"], "42")

    def test_warning_converted_to_string(self):
        dc = DiagnosticsCollector()
        dc.record_warning("src", Warning("heads up"))
        self.assertEqual(dc.warnings[0]["warning"], "heads up")

class TestToDict(unittest.TestCase):

    def test_all_top_level_keys(self):
        dc = DiagnosticsCollector()
        result = dc.to_dict()
        expected = {
            "run_metadata", "neo4j_queries", "entity_summary",
            "checks", "escalation_paths", "escalation_batches",
            "password_audit", "cross_domain_checks", "mssql_sccm",
            "check_ordering", "report_generation",
            "warnings", "errors",
        }
        self.assertEqual(set(result.keys()), expected)

    def test_empty_collector_query_summary(self):
        dc = DiagnosticsCollector()
        result = dc.to_dict()
        qs = result["neo4j_queries"]["summary"]
        self.assertEqual(qs["total_queries"], 0)
        self.assertEqual(qs["total_duration_ms"], 0)
        self.assertIsNone(qs["slowest_query"])

    def test_empty_collector_check_summary(self):
        dc = DiagnosticsCollector()
        result = dc.to_dict()
        cs = result["checks"]["summary"]
        self.assertEqual(cs["total_registered"], 0)
        self.assertEqual(cs["total_executed"], 0)
        self.assertEqual(cs["total_skipped"], 0)
        self.assertEqual(cs["total_with_findings"], 0)
        self.assertEqual(cs["total_with_zero_findings"], 0)
        self.assertEqual(cs["total_errored"], 0)
        self.assertEqual(cs["total_findings"], 0)
        self.assertEqual(cs["skipped_breakdown"], {})
        self.assertEqual(result["checks"]["skipped"], [])

    def test_total_registered_sums_executed_skipped_and_errored(self):
        dc = DiagnosticsCollector()
        dc.record_check(
            name="Ran", risk_level="High", category="C", entity_type="user",
            duration_ms=1, entities_input=0, entities_after_filter=0,
            filtered_breakdown={}, findings_count=0,
        )
        dc.record_skipped("Skipped1", "datasource_unavailable:mssql")
        dc.record_skipped("Skipped2", "datasource_unavailable:sccm")
        dc.record_error("check:Crashed", RuntimeError("boom"))
        cs = dc.to_dict()["checks"]["summary"]
        self.assertEqual(cs["total_executed"], 1)
        self.assertEqual(cs["total_skipped"], 2)
        self.assertEqual(cs["total_errored"], 1)
        self.assertEqual(cs["total_registered"], 4)

    def test_skipped_breakdown_groups_by_reason_prefix(self):
        dc = DiagnosticsCollector()
        dc.record_skipped("A", "datasource_unavailable:mssql")
        dc.record_skipped("B", "datasource_unavailable:sccm")
        dc.record_skipped("C", "unknown_requirement:typo")
        cs = dc.to_dict()["checks"]["summary"]
        self.assertEqual(cs["skipped_breakdown"]["datasource_unavailable"], 2)
        self.assertEqual(cs["skipped_breakdown"]["unknown_requirement"], 1)

    def test_query_summary_computed(self):
        dc = DiagnosticsCollector()
        dc.record_query(name="fast", duration_ms=10, result_count=5)
        dc.record_query(name="slow", duration_ms=500, result_count=100)
        result = dc.to_dict()
        qs = result["neo4j_queries"]["summary"]
        self.assertEqual(qs["total_queries"], 2)
        self.assertEqual(qs["total_duration_ms"], 510.0)
        self.assertEqual(qs["slowest_query"]["name"], "slow")
        self.assertEqual(qs["slowest_query"]["duration_ms"], 500)

    def test_queries_list_in_output(self):
        dc = DiagnosticsCollector()
        dc.record_query(name="q1", duration_ms=10, result_count=5)
        result = dc.to_dict()
        self.assertEqual(len(result["neo4j_queries"]["queries"]), 1)

    def test_check_summary_computed(self):
        dc = DiagnosticsCollector()
        dc.record_check(
            name="C1", risk_level="High", category="Cat1",
            entity_type="user", duration_ms=10,
            entities_input=100, entities_after_filter=90,
            filtered_breakdown={}, findings_count=5,
        )
        dc.record_check(
            name="C2", risk_level="High", category="Cat2",
            entity_type="user", duration_ms=20,
            entities_input=100, entities_after_filter=100,
            filtered_breakdown={}, findings_count=0,
        )
        dc.record_check(
            name="C3", risk_level="Critical", category="Cat3",
            entity_type="user", duration_ms=30,
            entities_input=50, entities_after_filter=50,
            filtered_breakdown={}, findings_count=10,
        )
        cs = dc.to_dict()["checks"]["summary"]
        self.assertEqual(cs["total_registered"], 3)
        self.assertEqual(cs["total_with_findings"], 2)
        self.assertEqual(cs["total_with_zero_findings"], 1)
        self.assertEqual(cs["total_findings"], 15)

    def test_by_risk_level(self):
        dc = DiagnosticsCollector()
        dc.record_check(
            name="C1", risk_level="High", category="Cat1",
            entity_type="user", duration_ms=10,
            entities_input=100, entities_after_filter=100,
            filtered_breakdown={}, findings_count=5,
        )
        dc.record_check(
            name="C2", risk_level="High", category="Cat2",
            entity_type="user", duration_ms=10,
            entities_input=100, entities_after_filter=100,
            filtered_breakdown={}, findings_count=0,
        )
        dc.record_check(
            name="C3", risk_level="Critical", category="Cat3",
            entity_type="user", duration_ms=10,
            entities_input=50, entities_after_filter=50,
            filtered_breakdown={}, findings_count=3,
        )
        by_risk = dc.to_dict()["checks"]["by_risk_level"]
        self.assertEqual(by_risk["High"]["checks_run"], 2)
        self.assertEqual(by_risk["High"]["checks_with_findings"], 1)
        self.assertEqual(by_risk["High"]["total_findings"], 5)
        self.assertEqual(by_risk["Critical"]["checks_run"], 1)
        self.assertEqual(by_risk["Critical"]["total_findings"], 3)

    def test_errored_check_count(self):
        dc = DiagnosticsCollector()
        dc.record_error("check:BadCheck", RuntimeError("fail"))
        dc.record_error("query:slow_query", TimeoutError("timeout"))
        cs = dc.to_dict()["checks"]["summary"]
        self.assertEqual(cs["total_errored"], 1)

    def test_run_metadata(self):
        dc = DiagnosticsCollector()
        dc.domains = ["TRAINING.LOCAL"]
        dc.args = {"mode": "ad_audit", "ad": True}
        meta = dc.to_dict()["run_metadata"]
        self.assertEqual(meta["domains"], ["TRAINING.LOCAL"])
        self.assertEqual(meta["mode"], "ad_audit")
        self.assertIn("timestamp", meta)
        self.assertIn("duration_seconds", meta)

    def test_run_metadata_default_mode(self):
        dc = DiagnosticsCollector()
        meta = dc.to_dict()["run_metadata"]
        self.assertEqual(meta["mode"], "unknown")

    def test_check_detail_in_output(self):
        dc = DiagnosticsCollector()
        dc.record_check(
            name="C1", risk_level="High", category="Cat1",
            entity_type="user", duration_ms=10,
            entities_input=100, entities_after_filter=100,
            filtered_breakdown={}, findings_count=5,
        )
        detail = dc.to_dict()["checks"]["detail"]
        self.assertEqual(len(detail), 1)
        self.assertEqual(detail[0]["name"], "C1")

    def test_passthrough_sections(self):
        dc = DiagnosticsCollector()
        dc.entity_summary = {"users": {"total": 100}}
        dc.escalation_paths = {"total_paths": 50}
        dc.password_audit = {"cracking_rate": 28.7}
        dc.cross_domain_checks = {"domains": 2}
        dc.check_order = {"High": ["Check1"]}
        dc.report_generation = {"json_generated": True}
        result = dc.to_dict()
        self.assertEqual(result["entity_summary"]["users"]["total"], 100)
        self.assertEqual(result["escalation_paths"]["total_paths"], 50)
        self.assertEqual(result["password_audit"]["cracking_rate"], 28.7)
        self.assertEqual(result["cross_domain_checks"]["domains"], 2)
        self.assertEqual(result["check_ordering"]["High"], ["Check1"])
        self.assertTrue(result["report_generation"]["json_generated"])

class TestWrite(unittest.TestCase):

    def test_writes_valid_json(self):
        dc = DiagnosticsCollector()
        dc.domains = ["TEST.LOCAL"]
        dc.record_query(name="q1", duration_ms=10, result_count=5)
        dc.record_check(
            name="C1", risk_level="High", category="Cat1",
            entity_type="user", duration_ms=10,
            entities_input=50, entities_after_filter=50,
            filtered_breakdown={}, findings_count=3,
        )
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            path = f.name
        try:
            dc.write(path)
            with open(path) as f:
                data = json.load(f)
            self.assertIn("run_metadata", data)
            self.assertEqual(data["run_metadata"]["domains"], ["TEST.LOCAL"])
            self.assertEqual(len(data["neo4j_queries"]["queries"]), 1)
        finally:
            os.unlink(path)

    def test_output_is_json_serializable(self):
        dc = DiagnosticsCollector()
        dc.record_query(name="q", duration_ms=1, result_count=0)
        dc.record_check(
            name="C", risk_level="Low", category="C",
            entity_type="computer", duration_ms=1,
            entities_input=0, entities_after_filter=0,
            filtered_breakdown={}, findings_count=0,
        )
        dc.record_error("test", ValueError("err"))
        result = dc.to_dict()
        serialized = json.dumps(result)
        self.assertIsInstance(serialized, str)

class TestDomainKeyedDiagnostics(unittest.TestCase):

    def test_compute_audit_mode_combined(self):
        self.assertEqual(compute_audit_mode("Training", "Training"), "ad_pwd_audit")

    def test_compute_audit_mode_branches(self):
        self.assertEqual(compute_audit_mode("Training", None), "ad_audit")
        self.assertEqual(compute_audit_mode(None, "Training"), "pwd_audit")
        self.assertEqual(compute_audit_mode(None, None), "interactive")
        self.assertEqual(compute_audit_mode("", ""), "interactive")

    def test_domain_keyed_fields_keep_two_writes(self):
        dc = DiagnosticsCollector()
        dc.escalation_paths["TRAINING.LOCAL"] = {"total_paths_computed": 100}
        dc.escalation_paths["SECRET.TRAINING.LOCAL"] = {"total_paths_computed": 5}
        dc.mssql_sccm["TRAINING.LOCAL"] = {"mssql": {"checks_run": 3}}
        dc.mssql_sccm["SECRET.TRAINING.LOCAL"] = {"mssql": {"checks_run": 0}}
        dc.report_generation["TRAINING.LOCAL"] = {"client_report.html": 1024}
        dc.report_generation["SECRET.TRAINING.LOCAL"] = {"client_report.html": 512}

        out = dc.to_dict()
        self.assertEqual(out["escalation_paths"]["TRAINING.LOCAL"]["total_paths_computed"], 100)
        self.assertEqual(out["escalation_paths"]["SECRET.TRAINING.LOCAL"]["total_paths_computed"], 5)
        self.assertEqual(out["mssql_sccm"]["TRAINING.LOCAL"]["mssql"]["checks_run"], 3)
        self.assertEqual(out["mssql_sccm"]["SECRET.TRAINING.LOCAL"]["mssql"]["checks_run"], 0)
        self.assertEqual(out["report_generation"]["TRAINING.LOCAL"]["client_report.html"], 1024)
        self.assertEqual(out["report_generation"]["SECRET.TRAINING.LOCAL"]["client_report.html"], 512)

    def test_cross_domain_checks_set_once_across_runs(self):
        from checks.cross_domain.manager import CrossDomainManager
        from checks.cross_domain.base import CrossDomainRegistry, CrossDomainCheck

        diagnostics = DiagnosticsCollector()

        class _Stub(CrossDomainCheck):
            CATEGORY_NAME = "stub"
            RISK_LEVEL = "Low"

            def run(self):
                return [{"x": 1}]

        with patch.object(CrossDomainRegistry, "get_all_checks", return_value=[_Stub]):
            manager = CrossDomainManager(dependencies=None, diagnostics=diagnostics)
            manager._run_single_check = lambda c: {
                "category": "stub", "risk_level": "Low",
                "findings": [{"x": 1}], "count": 1,
            }
            manager.run_all_checks()

            first = dict(diagnostics.cross_domain_checks)
            self.assertEqual(first["checks_run"], 1)
            self.assertEqual(first["total_findings"], 1)

            manager2 = CrossDomainManager(dependencies=None, diagnostics=diagnostics)
            manager2._run_single_check = lambda c: {
                "category": "stub", "risk_level": "Low",
                "findings": [{"x": 1}, {"y": 2}], "count": 2,
            }
            manager2.run_all_checks()

            self.assertEqual(diagnostics.cross_domain_checks, first)

class TestEntitySummaryDomainKeyed(unittest.TestCase):

    def _record_for_domain(self, diagnostics, domain, users, computers):
        from checks.core.manager import VulnerabilityFrameworkManager
        from checks.core.constants import DataTypes

        class _Neo4j:
            def __init__(self, d):
                self._domain_filter = d
                self.conn = None
                self.computer_sids = set()
            def get_domain_name(self):
                return self._domain_filter

        manager = VulnerabilityFrameworkManager(_Neo4j(domain), diagnostics=diagnostics)
        manager.shared_cache[DataTypes.USERS] = users
        manager.shared_cache[DataTypes.COMPUTERS] = computers
        manager._record_entity_summary()

    def test_two_domains_both_preserved(self):
        diagnostics = DiagnosticsCollector()
        self._record_for_domain(
            diagnostics, "TRAINING.LOCAL",
            users=[{"enabled": True, "isAdmin": True}] * 3153,
            computers=[{"enabled": True, "isDomainController": True}] * 124,
        )
        self._record_for_domain(
            diagnostics, "SECRET.TRAINING.LOCAL",
            users=[{"enabled": True}] * 92,
            computers=[{"enabled": False}] * 27,
        )

        self.assertEqual(diagnostics.entity_summary["TRAINING.LOCAL"]["users"]["total"], 3153)
        self.assertEqual(diagnostics.entity_summary["TRAINING.LOCAL"]["computers"]["total"], 124)
        self.assertEqual(diagnostics.entity_summary["SECRET.TRAINING.LOCAL"]["users"]["total"], 92)
        self.assertEqual(diagnostics.entity_summary["SECRET.TRAINING.LOCAL"]["computers"]["total"], 27)
