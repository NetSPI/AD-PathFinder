import pytest

from checks.common_group_escalation import CommonGroupEscalationCheck
from tests.check_harness import build_fake_account_analysis, load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_common_group_with_dangerous_relationship(clean_neo4j):
    load_fixture(clean_neo4j, "common_group_escalation.cypher")

    fake = build_fake_account_analysis(
        all_user_data=[{"enabled": True, "is_computer": False}],
    )
    findings = run_check(
        CommonGroupEscalationCheck,
        clean_neo4j,
        domain_filter="TEST.LOCAL",
        account_analysis=fake,
        preload_entity_sid_mappings=True,
    )

    assert CommonGroupEscalationCheck.RISK_LEVEL == "High"
    non_meta_keys = [k for k in findings if not k.startswith("___")]
    assert len(non_meta_keys) == 1
    assert "HELPDESK@TEST.LOCAL" in non_meta_keys
    assert isinstance(findings["HELPDESK@TEST.LOCAL"], list) and len(findings["HELPDESK@TEST.LOCAL"]) >= 1
