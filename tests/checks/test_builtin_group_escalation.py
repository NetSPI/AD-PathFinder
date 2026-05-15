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
    assert findings, "builtin_group_escalation should fire when a default group has a dangerous relationship"
    assert "Domain Users" in findings
