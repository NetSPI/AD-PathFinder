import pytest

from checks.user_constrained_delegation import UserConstrainedDelegationCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_constrained_delegation(clean_neo4j):
    load_fixture(clean_neo4j, "user_constrained_delegation.cypher")
    findings = run_check(UserConstrainedDelegationCheck, clean_neo4j)
    assert UserConstrainedDelegationCheck.RISK_LEVEL == "High"
    assert len(findings) == 1
    sid = "S-1-5-21-TEST-1100"
    assert sid in findings
    assert isinstance(findings[sid], str) and "Constrained Delegation:" in findings[sid]
