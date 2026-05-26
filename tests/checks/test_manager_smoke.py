import pytest

from checks.core.manager import VulnerabilityFrameworkManager
from modules.diagnostics import DiagnosticsCollector
from modules.neo4j_data import Neo4jData
from tests.check_harness import build_fake_account_analysis, load_fixture

pytestmark = pytest.mark.neo4j


def _run_manager(conn, *, fixture, **aa_kwargs):
    load_fixture(conn, fixture)
    neo4j_data = Neo4jData(conn, domain_filter="TEST.LOCAL")
    diagnostics = DiagnosticsCollector()
    aa_kwargs.setdefault("all_user_data", [])
    manager = VulnerabilityFrameworkManager(
        neo4j_data=neo4j_data,
        account_analysis=build_fake_account_analysis(**aa_kwargs),
        diagnostics=diagnostics,
    )
    display_content, stats_content = manager.run_all_checks()
    check_errors = [e for e in diagnostics.errors if e["source"].startswith("check:")]
    return display_content, stats_content, check_errors


def _find_block(display_content, category_name):
    for blocks in display_content.values():
        for block in blocks:
            if block["category"] == category_name:
                return block
    return None


def _assert_block_structure(block, category_name):
    assert block is not None, f"'{category_name}' not in display_content"
    for key in ("category", "count", "results", "check_instance"):
        assert key in block, f"Display block missing '{key}'"
    assert block["count"] > 0, f"'{category_name}' has count 0"
    assert isinstance(block["results"], dict), (
        f"'{category_name}' results is {type(block['results']).__name__}, expected dict"
    )


def _assert_stats_mirror(display_content, stats_content, category_name):
    risk = next(
        (level for level, blocks in display_content.items()
         if any(b["category"] == category_name for b in blocks)),
        None,
    )
    assert risk is not None, f"'{category_name}' not found in display_content"
    assert category_name in stats_content.get(risk, {}), (
        f"'{category_name}' in display_content but missing from stats_content"
    )
    block = _find_block(display_content, category_name)
    stat = stats_content[risk][category_name]
    assert stat["count"] == block["count"], (
        f"stats count {stat['count']} != display count {block['count']}"
    )
    assert stat["results"] is block["results"], "stats results is not the same object as display results"


def test_sccm_takeover6_visible_to_manager(clean_neo4j):
    display_content, stats_content, check_errors = _run_manager(
        clean_neo4j, fixture="sccm_takeover6.cypher",
    )
    category = "SCCM Hierarchy Takeover via SMB Relay to SMS Provider (TAKEOVER-6)"
    block = _find_block(display_content, category)
    _assert_block_structure(block, category)
    _assert_stats_mirror(display_content, stats_content, category)
    assert not check_errors, f"Unexpected check errors: {check_errors}"


def test_sccm_privilege_escalation_visible_to_manager(clean_neo4j):
    display_content, stats_content, check_errors = _run_manager(
        clean_neo4j, fixture="sccm_privilege_escalation.cypher",
    )
    category = "SCCM Privilege Escalation"
    block = _find_block(display_content, category)
    _assert_block_structure(block, category)
    _assert_stats_mirror(display_content, stats_content, category)
    assert not check_errors, f"Unexpected check errors: {check_errors}"


def test_esc1_visible_to_manager(clean_neo4j):
    display_content, stats_content, check_errors = _run_manager(
        clean_neo4j, fixture="esc1_vulnerable_template.cypher",
    )
    category = "ESC1 — Enrollee Supplies Subject"
    block = _find_block(display_content, category)
    _assert_block_structure(block, category)
    _assert_stats_mirror(display_content, stats_content, category)
    key = next(iter(block["results"]))
    assert "(" in key and " on " in key, (
        f"ADCS key should be 'Template (CA on host)', got: {key}"
    )
    assert not check_errors, f"Unexpected check errors: {check_errors}"


def test_smb_signing_visible_to_manager(clean_neo4j):
    display_content, stats_content, check_errors = _run_manager(
        clean_neo4j, fixture="smb_signing.cypher",
    )
    category = "Computers with SMB Signing Disabled"
    block = _find_block(display_content, category)
    _assert_block_structure(block, category)
    _assert_stats_mirror(display_content, stats_content, category)
    sid, value = next(iter(block["results"].items()))
    assert sid.startswith("S-1-5-"), f"Expected SID key, got: {sid}"
    assert isinstance(value, dict) and "inline_description" in value, (
        f"SMB finding should be inline dict, got: {value!r}"
    )
    assert not check_errors, f"Unexpected check errors: {check_errors}"
