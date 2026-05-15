import pytest

from checks.core.manager import VulnerabilityFrameworkManager
from modules.diagnostics import DiagnosticsCollector
from modules.neo4j_data import Neo4jData
from tests.check_harness import build_fake_account_analysis, load_fixture

pytestmark = pytest.mark.neo4j


def _run_manager(conn, *, fixture):
    load_fixture(conn, fixture)
    neo4j_data = Neo4jData(conn, domain_filter="TEST.LOCAL")
    diagnostics = DiagnosticsCollector()
    # common_group_escalation.execute() dereferences account_analysis.get_all_user_data();
    # an empty fake lets it short-circuit instead of raising into the manager catch.
    manager = VulnerabilityFrameworkManager(
        neo4j_data=neo4j_data,
        account_analysis=build_fake_account_analysis(all_user_data=[]),
        diagnostics=diagnostics,
    )
    display_content, _stats = manager.run_all_checks()
    categories = {
        block["check_instance"].CATEGORY_NAME
        for blocks in display_content.values()
        for block in blocks
    }
    check_errors = [e for e in diagnostics.errors if e["source"].startswith("check:")]
    return categories, check_errors


def test_sccm_takeover6_visible_to_manager(clean_neo4j):
    categories, check_errors = _run_manager(clean_neo4j, fixture="sccm_takeover6.cypher")
    assert "SCCM Hierarchy Takeover via SMB Relay to SMS Provider (TAKEOVER-6)" in categories
    assert not check_errors, f"Unexpected check errors: {check_errors}"


def test_mssql_sccm_visible_to_manager(clean_neo4j):
    categories, check_errors = _run_manager(clean_neo4j, fixture="mssql_sccm.cypher")
    assert "SCCM Database Compromise" in categories
    assert not check_errors, f"Unexpected check errors: {check_errors}"
