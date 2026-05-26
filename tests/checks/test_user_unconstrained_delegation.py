import pytest

from checks.user_unconstrained_delegation import UserUnconstrainedDelegationCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_unconstrained_delegation(clean_neo4j):
    load_fixture(clean_neo4j, "user_unconstrained_delegation.cypher")
    findings = run_check(UserUnconstrainedDelegationCheck, clean_neo4j)
    assert UserUnconstrainedDelegationCheck.RISK_LEVEL == "High"
    assert len(findings) == 1
    assert "S-1-5-21-TEST-1100" in findings
    assert findings["S-1-5-21-TEST-1100"] == ""
