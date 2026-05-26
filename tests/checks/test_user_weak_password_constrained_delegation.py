import pytest

from checks.user_weak_password_constrained_delegation import UserWeakPasswordConstrainedDelegationCheck
from tests.check_harness import build_fake_account_analysis, load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_only_for_weak_password_with_constrained_delegation(clean_neo4j):
    load_fixture(clean_neo4j, "user_weak_password_constrained_delegation.cypher")

    fake = build_fake_account_analysis(weak_passwords=["alice", "bob"])
    findings = run_check(
        UserWeakPasswordConstrainedDelegationCheck,
        clean_neo4j,
        account_analysis=fake,
        preload_entity_sid_mappings=True,
    )

    assert len(findings) == 1
    assert UserWeakPasswordConstrainedDelegationCheck.RISK_LEVEL == "Critical"
    assert "S-1-5-21-TEST-2600" in findings
    assert isinstance(findings["S-1-5-21-TEST-2600"], str)
    assert "Constrained Delegation:" in findings["S-1-5-21-TEST-2600"]
    assert "S-1-5-21-TEST-2601" not in findings
