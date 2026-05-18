import pytest

from checks.cross_domain.base import CrossDomainDependencies
from checks.cross_domain.cross_domain_escalation_path import CrossDomainEscalationPathCheck
from tests.check_harness import load_fixture

pytestmark = pytest.mark.neo4j


def test_fires_on_cross_domain_user_path_to_da(clean_neo4j):
    load_fixture(clean_neo4j, "cross_domain_escalation_path.cypher")

    deps = CrossDomainDependencies(
        conn=clean_neo4j,
        all_domains=["TEST.LOCAL", "OTHER.LOCAL"],
        relationship_pattern="MemberOf|AdminTo|GenericAll",
    )
    assert CrossDomainEscalationPathCheck.RISK_LEVEL == "Critical"
    findings = CrossDomainEscalationPathCheck(deps).run()

    assert len(findings) == 1
    match = findings[0]
    assert match["source_sid"] == "S-1-5-21-TEST-4000"
    assert match["target_domain"] == "OTHER.LOCAL"
    assert match["target_type"] == "Domain Admin"
    assert match["fullPath"], "fullPath should not be empty"


def test_fires_on_multi_hop_cross_domain_path(clean_neo4j):
    load_fixture(clean_neo4j, "cross_domain_escalation_path_via_trust.cypher")

    deps = CrossDomainDependencies(
        conn=clean_neo4j,
        all_domains=["CORP.LOCAL", "PARTNER.LOCAL"],
        relationship_pattern="MemberOf|AdminTo|GenericAll",
    )
    findings = CrossDomainEscalationPathCheck(deps).run()

    assert len(findings) == 1
    match = findings[0]
    assert match["source_sid"] == "S-1-5-21-CORP-5000"
    assert match["source_domain"] == "CORP.LOCAL"
    assert match["target_domain"] == "PARTNER.LOCAL"
    assert match["target_type"] == "Domain Admin"
    assert len(match["fullPath"]) >= 3, "Multi-hop path should have 3+ nodes"


def test_to_display_results_key_format(clean_neo4j):
    load_fixture(clean_neo4j, "cross_domain_escalation_path_via_trust.cypher")

    deps = CrossDomainDependencies(
        conn=clean_neo4j,
        all_domains=["CORP.LOCAL", "PARTNER.LOCAL"],
        relationship_pattern="MemberOf|AdminTo|GenericAll",
    )
    findings = CrossDomainEscalationPathCheck(deps).run()
    assert len(findings) > 0

    display = CrossDomainEscalationPathCheck.to_display_results(findings)
    total = display.pop("__total_user_count__", None)
    assert total is not None and total > 0, "__total_user_count__ should be positive"

    assert len(display) > 0, "to_display_results returned no display entries"
    for key, value in display.items():
        assert key.startswith("Users with Shared Path ("), (
            f"Display key should start with 'Users with Shared Path (', got: {key}"
        )
        assert "Cross-Domain Path:" in value, (
            f"Display value should contain 'Cross-Domain Path:', got: {value}"
        )


def test_to_display_results_filters_by_source_domain(clean_neo4j):
    load_fixture(clean_neo4j, "cross_domain_escalation_path_via_trust.cypher")

    deps = CrossDomainDependencies(
        conn=clean_neo4j,
        all_domains=["CORP.LOCAL", "PARTNER.LOCAL"],
        relationship_pattern="MemberOf|AdminTo|GenericAll",
    )
    findings = CrossDomainEscalationPathCheck(deps).run()

    display_corp = CrossDomainEscalationPathCheck.to_display_results(
        findings, source_domain="CORP.LOCAL",
    )
    display_corp.pop("__total_user_count__", None)
    assert len(display_corp) > 0, "CORP.LOCAL findings should produce display entries"

    display_none = CrossDomainEscalationPathCheck.to_display_results(
        findings, source_domain="NONEXISTENT.LOCAL",
    )
    assert display_none == {}, "Non-matching domain should return empty dict"


def test_to_display_results_empty_findings():
    display = CrossDomainEscalationPathCheck.to_display_results([])
    assert display == {}
