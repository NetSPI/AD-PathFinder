import unittest

from checks.core import Check, check
from checks.core.constants import DataTypes
from checks.core.datasource import DataSource, DataSourceRegistry, datasource
from checks.core.manager import VulnerabilityFrameworkManager
from checks.core.registry import CheckRegistry
from modules.diagnostics import DiagnosticsCollector
from modules.main import _record_diagnostics_domains

class FakeNeo4jData:
    def __init__(self):
        self.conn = None
        self.computer_sids = set()

    def populate_group_sid_mappings(self):
        pass

    def get_admin_users_and_computers(self):
        return [], []

    def get_all_users_with_attributes(self):
        return []

    def get_all_computers_with_attributes(self):
        return []

    def get_entity_counts(self):
        return {}

class FakeDomainNeo4jData(FakeNeo4jData):
    def __init__(self, domain):
        super().__init__()
        self._domain_filter = domain

class TestFrameworkHardeningDiagnostics(unittest.TestCase):
    def setUp(self):
        import datasources  # Ensure manager's import does not register platform DataSources mid-test.

        self._orig_checks = list(CheckRegistry.checks)
        self._orig_datasources = dict(DataSourceRegistry._datasources)
        DataSourceRegistry._datasources = {}

    def tearDown(self):
        CheckRegistry.checks = self._orig_checks
        DataSourceRegistry._datasources = self._orig_datasources

    def _run_manager(self, neo4j_data=None, check_datasources=False):
        diagnostics = DiagnosticsCollector()
        manager = VulnerabilityFrameworkManager(
            neo4j_data or FakeNeo4jData(),
            diagnostics=diagnostics,
        )
        if not check_datasources:
            manager._check_datasource_availability = lambda: None
        manager.run_all_checks()
        return diagnostics

    def test_check_exception_records_check_error(self):
        CheckRegistry.checks = []

        @check(risk="High", category="Exploding Check", data=[])
        class ExplodingCheck(Check):
            def execute(self):
                raise RuntimeError("boom")

        diagnostics = self._run_manager()

        self.assertEqual(
            [e["source"] for e in diagnostics.errors],
            ["check:ExplodingCheck"],
        )
        self.assertIn("boom", diagnostics.errors[0]["error"])

    def test_preload_exception_records_preload_error(self):
        CheckRegistry.checks = []

        @check(risk="Low", category="Needs Computers", data=[DataTypes.COMPUTERS])
        class NeedsComputersCheck(Check):
            def execute(self):
                return {}

        class BrokenPreloadNeo4jData(FakeNeo4jData):
            def get_all_computers_with_attributes(self):
                raise RuntimeError("computer preload failed")

        diagnostics = self._run_manager(BrokenPreloadNeo4jData())

        sources = [e["source"] for e in diagnostics.errors]
        self.assertIn(f"preload:{DataTypes.COMPUTERS}", sources)

    def test_entity_summary_exception_records_error_and_continues_checks(self):
        CheckRegistry.checks = []
        ran = {"value": False}

        @check(risk="Low", category="Survives Summary Failure", data=[])
        class SurvivesSummaryFailureCheck(Check):
            def execute(self):
                ran["value"] = True
                return {}

        class BrokenEntitySummaryNeo4jData(FakeNeo4jData):
            def get_entity_counts(self):
                raise RuntimeError("entity summary failed")

        diagnostics = self._run_manager(BrokenEntitySummaryNeo4jData())

        self.assertTrue(ran["value"])
        summary_errors = [
            error for error in diagnostics.errors
            if error["source"] == "entity_summary"
        ]
        self.assertEqual(len(summary_errors), 1)
        self.assertIn("entity summary failed", summary_errors[0]["error"])

    def test_datasource_exception_records_datasource_error_and_skips_check(self):
        CheckRegistry.checks = []
        ran = {"value": False}

        @datasource("broken_platform")
        class BrokenPlatform(DataSource):
            def available(self):
                raise RuntimeError("datasource unavailable")

        @check(risk="Medium", category="Requires Broken Platform", data=[], requires=["broken_platform"])
        class RequiresBrokenPlatformCheck(Check):
            def execute(self):
                ran["value"] = True
                return {"unexpected": "bug"}

        diagnostics = self._run_manager(check_datasources=True)

        self.assertFalse(ran["value"])
        self.assertEqual(
            [e["source"] for e in diagnostics.errors],
            ["datasource:broken_platform"],
        )

    def test_unknown_datasource_requirement_records_error_and_skips_check(self):
        CheckRegistry.checks = []
        ran = {"value": False}

        @check(risk="Medium", category="Requires Typo", data=[], requires=["typo_platform"])
        class RequiresTypoPlatformCheck(Check):
            def execute(self):
                ran["value"] = True
                return {"unexpected": "bug"}

        diagnostics = self._run_manager()

        self.assertFalse(ran["value"])
        self.assertEqual(diagnostics.errors, [])
        self.assertEqual(
            [(s["name"], s["reason"]) for s in diagnostics.skipped],
            [("RequiresTypoPlatformCheck", "unknown_requirement:typo_platform")],
        )
        summary = diagnostics.to_dict()["checks"]["summary"]
        self.assertEqual(summary["total_registered"], 1)
        self.assertEqual(summary["total_executed"], 0)
        self.assertEqual(summary["total_skipped"], 1)
        self.assertEqual(summary["total_errored"], 0)

    def test_unavailable_datasource_records_skip_with_reason(self):
        CheckRegistry.checks = []
        ran = {"value": False}

        @datasource("offline_platform")
        class OfflinePlatform(DataSource):
            def available(self):
                return False

        @check(risk="Medium", category="Needs Offline", data=[], requires=["offline_platform"])
        class NeedsOfflineCheck(Check):
            def execute(self):
                ran["value"] = True
                return {"unexpected": "bug"}

        diagnostics = self._run_manager(check_datasources=True)

        self.assertFalse(ran["value"])
        self.assertEqual(
            [(s["name"], s["reason"]) for s in diagnostics.skipped],
            [("NeedsOfflineCheck", "datasource_unavailable:offline_platform")],
        )

    def test_skip_records_domain_when_manager_has_domain_filter(self):
        CheckRegistry.checks = []

        @datasource("domain_offline")
        class DomainOfflinePlatform(DataSource):
            def available(self):
                return False

        @check(risk="Medium", category="Needs Domain Offline", data=[], requires=["domain_offline"])
        class NeedsDomainOfflineCheck(Check):
            def execute(self):
                return {"unexpected": "bug"}

        diagnostics = self._run_manager(
            FakeDomainNeo4jData("secret.training.local"),
            check_datasources=True,
        )

        self.assertEqual(diagnostics.skipped[0]["domain"], "secret.training.local")

    def test_check_detail_and_platform_summary_per_domain(self):
        CheckRegistry.checks = []

        @check(risk="High", category="MSSQL Test", data=[])
        class MSSQLTestCheck(Check):
            def execute(self):
                diagnostics.record_query(
                    name=f"mssql_test_{self.neo4j_data._domain_filter}",
                    duration_ms=25,
                    result_count=1,
                )
                return {self.neo4j_data._domain_filter: "finding"}

        diagnostics = DiagnosticsCollector()
        for domain in ("training.local", "secret.training.local"):
            manager = VulnerabilityFrameworkManager(
                FakeDomainNeo4jData(domain),
                diagnostics=diagnostics,
            )
            manager._check_datasource_availability = lambda: None
            manager.run_all_checks()

        self.assertEqual(
            [c["domain"] for c in diagnostics.checks],
            ["training.local", "secret.training.local"],
        )
        self.assertEqual(diagnostics.mssql_sccm["training.local"]["mssql"]["checks_run"], 1)
        self.assertEqual(diagnostics.mssql_sccm["training.local"]["mssql"]["total_findings"], 1)
        self.assertEqual(diagnostics.mssql_sccm["training.local"]["mssql"]["queries_run"], 1)
        self.assertEqual(diagnostics.mssql_sccm["training.local"]["mssql"]["query_duration_ms"], 25)
        self.assertEqual(
            diagnostics.mssql_sccm["training.local"]["mssql"]["slowest_check"]["name"],
            "MSSQLTestCheck",
        )
        self.assertEqual(diagnostics.mssql_sccm["secret.training.local"]["mssql"]["checks_run"], 1)
        self.assertEqual(diagnostics.mssql_sccm["secret.training.local"]["mssql"]["total_findings"], 1)
        self.assertEqual(diagnostics.mssql_sccm["secret.training.local"]["mssql"]["queries_run"], 1)

    def test_platform_summary_groups_sccm_takeover_query_names(self):
        diagnostics = DiagnosticsCollector()
        diagnostics.record_check(
            name="SCCMTestCheck",
            risk_level="Critical",
            category="SCCM Test",
            entity_type="computer",
            duration_ms=50,
            entities_input=0,
            entities_after_filter=0,
            filtered_breakdown={},
            findings_count=1,
            domain="training.local",
        )
        diagnostics.record_query(
            name="takeover1_edge_paths",
            duration_ms=42,
            result_count=1,
        )
        manager = VulnerabilityFrameworkManager(
            FakeDomainNeo4jData("training.local"),
            diagnostics=diagnostics,
        )
        manager._diagnostic_query_start_index = 0
        manager._record_platform_summary()
        sccm_summary = diagnostics.mssql_sccm["training.local"]["sccm"]

        self.assertEqual(sccm_summary["queries_run"], 1)
        self.assertEqual(sccm_summary["slowest_query"]["name"], "takeover1_edge_paths")

    def test_record_diagnostics_domains_keeps_all_discovered_domains(self):
        diagnostics = DiagnosticsCollector()
        diagnostics.domains = ["training.local"]

        _record_diagnostics_domains(
            diagnostics,
            ["training.local", "secret.training.local", "third.local"],
        )

        self.assertEqual(
            diagnostics.domains,
            ["training.local", "secret.training.local", "third.local"],
        )

    def test_import_errors_recorded_into_diagnostics(self):
        CheckRegistry.checks = []
        import checks as checks_pkg
        import checks.cross_domain as cross_domain_pkg

        original_checks = list(checks_pkg.IMPORT_ERRORS)
        original_cross = list(cross_domain_pkg.IMPORT_ERRORS)
        checks_pkg.IMPORT_ERRORS.append({
            "module": "broken_check",
            "error_type": "SyntaxError",
            "message": "invalid syntax (broken_check.py, line 3)",
        })
        cross_domain_pkg.IMPORT_ERRORS.append({
            "module": "broken_xd",
            "error_type": "ImportError",
            "message": "No module named 'missing_dep'",
        })

        try:
            diagnostics = self._run_manager()
        finally:
            checks_pkg.IMPORT_ERRORS[:] = original_checks
            cross_domain_pkg.IMPORT_ERRORS[:] = original_cross

        sources = [e["source"] for e in diagnostics.errors]
        self.assertIn("import:checks.broken_check", sources)
        self.assertIn("import:checks.cross_domain.broken_xd", sources)
        broken = next(e for e in diagnostics.errors if e["source"] == "import:checks.broken_check")
        self.assertIn("SyntaxError", broken["error"])

    def test_import_errors_not_duplicated_across_runs_with_shared_diagnostics(self):
        CheckRegistry.checks = []
        import checks as checks_pkg

        original = list(checks_pkg.IMPORT_ERRORS)
        checks_pkg.IMPORT_ERRORS.append({
            "module": "noisy_check",
            "error_type": "ImportError",
            "message": "x",
        })

        try:
            diagnostics = DiagnosticsCollector()
            for _ in range(3):
                manager = VulnerabilityFrameworkManager(FakeNeo4jData(), diagnostics=diagnostics)
                manager._check_datasource_availability = lambda: None
                manager.run_all_checks()
        finally:
            checks_pkg.IMPORT_ERRORS[:] = original

        recorded = [e for e in diagnostics.errors if e["source"] == "import:checks.noisy_check"]
        self.assertEqual(len(recorded), 1, "import error should be recorded once across multiple runs")
