"""Single-domain regression: when len(all_domains) == 1, the multi-domain
common path must route to _run_single_domain_audit with the top-level reporting
object (the one fed by main.py's unfiltered top-level Neo4jData). The audit-context refactor
moved per-domain ownership onto MultiDomainAuditContext but the top-level
Reporting object survives for this branch — that wiring is what's at risk."""

import unittest
from unittest.mock import MagicMock, patch

from modules import main as main_module

def _make_audit_context(domains):
    ctx = MagicMock()
    ctx.diagnostics = None
    ctx.all_domains = list(domains)
    ctx.domain_hashes = {}
    ctx.ntds_file_path = None
    ctx.ntds_entries_loaded = True
    ctx.cross_domain_results = {}
    ctx.hashcat_file_path = None
    ctx.cracked_passwords_global = {}
    return ctx

class TestSingleDomainRouting(unittest.TestCase):

    def test_one_domain_routes_to_single_domain_audit(self):
        ctx = _make_audit_context(["TRAINING.LOCAL"])
        single_reporting = MagicMock()
        single_reporting.neo4j_data.get_domain_name.return_value = "TRAINING.LOCAL"
        gen_reports = MagicMock()

        with patch.object(main_module, "run_client_report_generation"), \
             patch.object(main_module, "_record_final_inventory"):
            result = main_module._run_multi_domain_audit_common(
                ctx, ["acme"], unsafe_report_enabled=False,
                audit_label="audit", require_ntds=False,
                generate_reports=gen_reports,
                single_domain_reporting=single_reporting,
            )

        self.assertTrue(result)
        gen_reports.assert_called_once()
        called_reporting = gen_reports.call_args[0][0]
        self.assertIs(called_reporting, single_reporting)

    def test_zero_domains_also_routes_single_domain(self):
        ctx = _make_audit_context([])
        single_reporting = MagicMock()
        single_reporting.neo4j_data.get_domain_name.return_value = "TRAINING.LOCAL"
        gen_reports = MagicMock()

        with patch.object(main_module, "run_client_report_generation"), \
             patch.object(main_module, "_record_final_inventory"):
            result = main_module._run_multi_domain_audit_common(
                ctx, [], unsafe_report_enabled=False,
                audit_label="audit", require_ntds=False,
                generate_reports=gen_reports,
                single_domain_reporting=single_reporting,
            )

        self.assertTrue(result)
        gen_reports.assert_called_once()

    def test_single_domain_without_reporting_returns_none(self):
        ctx = _make_audit_context(["TRAINING.LOCAL"])
        gen_reports = MagicMock()

        result = main_module._run_multi_domain_audit_common(
            ctx, ["acme"], unsafe_report_enabled=False,
            audit_label="audit", require_ntds=False,
            generate_reports=gen_reports,
            single_domain_reporting=None,
        )
        self.assertIsNone(result)
        gen_reports.assert_not_called()

    def test_single_domain_records_final_inventory_with_diagnostics(self):
        ctx = _make_audit_context(["TRAINING.LOCAL"])
        ctx.diagnostics = MagicMock()
        single_reporting = MagicMock()
        single_reporting.neo4j_data.get_domain_name.return_value = "TRAINING.LOCAL"
        gen_reports = MagicMock()

        with patch.object(main_module, "run_client_report_generation") as cr, \
             patch.object(main_module, "_record_final_inventory") as fi:
            main_module._run_multi_domain_audit_common(
                ctx, ["acme"], unsafe_report_enabled=False,
                audit_label="audit", require_ntds=False,
                generate_reports=gen_reports,
                single_domain_reporting=single_reporting,
            )

        cr.assert_called_once_with("report_training.local", "TRAINING.LOCAL")
        fi.assert_called_once_with("report_training.local", "TRAINING.LOCAL", ctx.diagnostics)

    def test_two_domains_does_not_route_single_domain(self):
        ctx = _make_audit_context(["A.LOCAL", "B.LOCAL"])
        ctx.get_domain_neo4j_data = MagicMock()

        per_domain_nd = MagicMock()
        per_domain_nd.get_domain_name.return_value = "A.LOCAL"
        ctx.get_domain_neo4j_data.return_value = per_domain_nd
        ctx.get_ntlmv2_hashes_for_domain = MagicMock(return_value={})

        single_reporting = MagicMock()
        gen_reports = MagicMock()

        with patch.object(main_module, "run_client_report_generation"), \
             patch.object(main_module, "_record_final_inventory"), \
             patch.object(main_module, "AccountAnalysis") as account_cls, \
             patch.object(main_module, "Analysis"), \
             patch.object(main_module, "Reporting") as reporting_cls:
            account_cls.return_value.has_enabled_cracked_accounts.return_value = True
            reporting_cls.return_value = MagicMock()
            main_module._run_multi_domain_audit_common(
                ctx, ["acme"], unsafe_report_enabled=False,
                audit_label="audit", require_ntds=False,
                generate_reports=gen_reports,
                single_domain_reporting=single_reporting,
            )

        for call in gen_reports.call_args_list:
            self.assertIsNot(call[0][0], single_reporting,
                             "two-domain path must build its own per-domain Reporting "
                             "and not reuse the single-domain one")
        self.assertEqual(gen_reports.call_count, 2)
