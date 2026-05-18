import pytest

from checks.cross_domain.base import CrossDomainDependencies
from checks.cross_domain.cross_domain_computer_escalation_path import CrossDomainComputerEscalationPathCheck
from tests.check_harness import load_fixture

pytestmark = pytest.mark.neo4j


def test_fires_on_cross_domain_computer_path_to_da(clean_neo4j):
    load_fixture(clean_neo4j, "cross_domain_computer_escalation_path.cypher")

    deps = CrossDomainDependencies(
        conn=clean_neo4j,
        all_domains=["TEST.LOCAL", "OTHER.LOCAL"],
        relationship_pattern="MemberOf|AdminTo|GenericAll",
    )
    assert CrossDomainComputerEscalationPathCheck.RISK_LEVEL == "High"
    findings = CrossDomainComputerEscalationPathCheck(deps).run()

    assert len(findings) == 1
    match = findings[0]
    assert match["source_sid"] == "S-1-5-21-TEST-4100"
    assert match["target_domain"] == "OTHER.LOCAL"
    assert match["target_type"] == "Domain Admin"
    assert match["fullPath"], "fullPath should not be empty"


def test_fires_on_multi_hop_cross_domain_path(clean_neo4j):
    load_fixture(clean_neo4j, "cross_domain_computer_escalation_path_via_trust.cypher")

    deps = CrossDomainDependencies(
        conn=clean_neo4j,
        all_domains=["CORP.LOCAL", "PARTNER.LOCAL"],
        relationship_pattern="MemberOf|AdminTo|GenericAll",
    )
    findings = CrossDomainComputerEscalationPathCheck(deps).run()

    assert len(findings) == 1
    match = findings[0]
    assert match["source_sid"] == "S-1-5-21-CORP-7000"
    assert match["source_domain"] == "CORP.LOCAL"
    assert match["target_domain"] == "PARTNER.LOCAL"
    assert match["target_type"] == "Domain Admin"
    assert len(match["fullPath"]) >= 3, "Multi-hop path should have 3+ nodes"


def test_to_display_results_key_format(clean_neo4j):
    load_fixture(clean_neo4j, "cross_domain_computer_escalation_path_via_trust.cypher")

    deps = CrossDomainDependencies(
        conn=clean_neo4j,
        all_domains=["CORP.LOCAL", "PARTNER.LOCAL"],
        relationship_pattern="MemberOf|AdminTo|GenericAll",
    )
    findings = CrossDomainComputerEscalationPathCheck(deps).run()
    assert len(findings) > 0

    display = CrossDomainComputerEscalationPathCheck.to_display_results(findings)
    total = display.pop("__total_user_count__", None)
    assert total is not None and total > 0
    assert len(display) > 0
    for key, value in display.items():
        assert key.startswith("Computers with Shared Path (")
        assert "Cross-Domain Path:" in value
