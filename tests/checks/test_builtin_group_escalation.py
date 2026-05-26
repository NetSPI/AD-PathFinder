import pytest

from checks.builtin_group_escalation import BuiltinGroupEscalationCheck
from tests.check_harness import build_fake_account_analysis, load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_default_group_with_dangerous_relationship(clean_neo4j):
    load_fixture(clean_neo4j, "builtin_group_escalation.cypher")

    findings = run_check(
        BuiltinGroupEscalationCheck,
        clean_neo4j,
        domain_filter="TEST.LOCAL",
        account_analysis=build_fake_account_analysis(),
    )
    assert BuiltinGroupEscalationCheck.RISK_LEVEL == "Critical"
    non_meta = {k: v for k, v in findings.items() if not k.startswith("___")}
    assert len(non_meta) == 1
    assert "Domain Users" in findings
    assert isinstance(findings["Domain Users"], list) and len(findings["Domain Users"]) >= 1
