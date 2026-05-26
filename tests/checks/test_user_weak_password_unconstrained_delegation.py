import pytest

from checks.user_weak_password_unconstrained_delegation import UserWeakPasswordUnconstrainedDelegationCheck
from tests.check_harness import build_fake_account_analysis, load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_only_for_weak_password_with_unconstrained_delegation(clean_neo4j):
    load_fixture(clean_neo4j, "user_weak_password_unconstrained_delegation.cypher")

    fake = build_fake_account_analysis(weak_passwords=["alice", "bob"])
    findings = run_check(
        UserWeakPasswordUnconstrainedDelegationCheck,
        clean_neo4j,
        account_analysis=fake,
        preload_entity_sid_mappings=True,
    )

    assert len(findings) == 1
    assert UserWeakPasswordUnconstrainedDelegationCheck.RISK_LEVEL == "Critical"
    assert "S-1-5-21-TEST-2700" in findings
    assert findings["S-1-5-21-TEST-2700"] == ""
    assert "S-1-5-21-TEST-2701" not in findings
