import unittest

from modules.diagnostics import DiagnosticsCollector
from modules.neo4j_connection import InstrumentedConnection
from checks.cross_domain.base import CrossDomainDependencies

class _FakeRawConnection:
    def __init__(self):
        self._pool = []
        self._next_results = [{"id": 1}]
        self.next_should_fail = False
        self.next_exception = None
        self.thread_conns = []

    def query(self, query, parameters=None, db=None):
        if self.next_exception:
            raise self.next_exception
        if self.next_should_fail:
            return None
        return list(self._next_results)

    def get_connection_for_thread(self):
        worker = _FakeRawConnection()
        self.thread_conns.append(worker)
        return worker

    def return_connection_to_pool(self, conn):
        self._pool.append(conn)

class TestInstrumentedConnectionWrapping(unittest.TestCase):

    def test_idempotent_wrapping_collapses_to_one_layer(self):
        raw = _FakeRawConnection()
        collector = DiagnosticsCollector()
        once = InstrumentedConnection(raw, collector)
        twice = InstrumentedConnection(once, collector)
        self.assertIs(twice._conn, raw)
        self.assertIs(twice._collector, collector)

    def test_idempotent_wrapping_records_single_query(self):
        raw = _FakeRawConnection()
        collector = DiagnosticsCollector()
        wrapped_twice = InstrumentedConnection(
            InstrumentedConnection(raw, collector), collector
        )
        wrapped_twice.query("MATCH (n) RETURN n", name="probe")
        self.assertEqual(len(collector.queries), 1)
        self.assertEqual(collector.queries[0]["name"], "probe")

class TestInstrumentedConnectionThreadPool(unittest.TestCase):

    def test_get_connection_for_thread_returns_wrapped_with_same_collector(self):
        raw = _FakeRawConnection()
        collector = DiagnosticsCollector()
        wrapped = InstrumentedConnection(raw, collector)
        worker = wrapped.get_connection_for_thread()
        self.assertIsInstance(worker, InstrumentedConnection)
        self.assertIs(worker._collector, collector)

    def test_worker_query_records_named_entry(self):
        raw = _FakeRawConnection()
        collector = DiagnosticsCollector()
        wrapped = InstrumentedConnection(raw, collector)
        worker = wrapped.get_connection_for_thread()
        worker.query("MATCH (n) RETURN n", name="find_escalation_paths")
        names = [q["name"] for q in collector.queries]
        self.assertIn("find_escalation_paths", names)
        self.assertNotIn("unnamed", names)

    def test_return_connection_to_pool_unwraps_before_delegating(self):
        raw = _FakeRawConnection()
        collector = DiagnosticsCollector()
        wrapped = InstrumentedConnection(raw, collector)
        worker = wrapped.get_connection_for_thread()
        wrapped.return_connection_to_pool(worker)
        self.assertEqual(len(raw._pool), 1)
        self.assertNotIsInstance(raw._pool[0], InstrumentedConnection)
        self.assertIs(raw._pool[0], worker._conn)

    def test_two_checkout_return_cycles_share_collector(self):
        raw = _FakeRawConnection()
        collector = DiagnosticsCollector()
        wrapped = InstrumentedConnection(raw, collector)

        first = wrapped.get_connection_for_thread()
        wrapped.return_connection_to_pool(first)
        second = wrapped.get_connection_for_thread()

        self.assertIs(first._collector, second._collector)
        self.assertNotIsInstance(second._conn, InstrumentedConnection)

class TestInstrumentedConnectionRecordsSuccessFlag(unittest.TestCase):

    def test_successful_query_omits_success_key(self):
        raw = _FakeRawConnection()
        collector = DiagnosticsCollector()
        wrapped = InstrumentedConnection(raw, collector)
        wrapped.query("MATCH (n) RETURN n", name="ok_q")
        self.assertEqual(len(collector.queries), 1)
        entry = collector.queries[0]
        self.assertNotIn("success", entry)
        self.assertEqual(entry["result_count"], 1)

    def test_failing_query_records_success_false_and_zero_results(self):
        raw = _FakeRawConnection()
        raw.next_should_fail = True
        collector = DiagnosticsCollector()
        wrapped = InstrumentedConnection(raw, collector)
        result = wrapped.query("MATCH (n) RETURN n", name="bad_q")
        self.assertIsNone(result)
        self.assertEqual(len(collector.queries), 1)
        entry = collector.queries[0]
        self.assertEqual(entry["success"], False)
        self.assertEqual(entry["result_count"], 0)
        self.assertEqual(entry["name"], "bad_q")

    def test_raised_query_records_success_false_and_reraises(self):
        raw = _FakeRawConnection()
        raw.next_exception = RuntimeError("driver exploded")
        collector = DiagnosticsCollector()
        wrapped = InstrumentedConnection(raw, collector)

        with self.assertRaisesRegex(RuntimeError, "driver exploded"):
            wrapped.query("MATCH (n) RETURN n", name="raised_q")

        self.assertEqual(len(collector.queries), 1)
        entry = collector.queries[0]
        self.assertEqual(entry["success"], False)
        self.assertEqual(entry["result_count"], 0)
        self.assertEqual(entry["name"], "raised_q")

class TestCrossDomainDependenciesWiring(unittest.TestCase):

    def test_dependencies_carry_diagnostics(self):
        raw = _FakeRawConnection()
        collector = DiagnosticsCollector()
        wrapped = InstrumentedConnection(raw, collector)

        deps = CrossDomainDependencies(
            conn=wrapped,
            all_domains=["TRAINING.LOCAL"],
            diagnostics=collector,
        )
        self.assertIs(deps.diagnostics, collector)
        self.assertIsInstance(deps.conn, InstrumentedConnection)

    def test_dependencies_default_diagnostics_none(self):
        raw = _FakeRawConnection()
        deps = CrossDomainDependencies(conn=raw, all_domains=[])
        self.assertIsNone(deps.diagnostics)
