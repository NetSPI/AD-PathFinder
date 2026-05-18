import pytest

from checks.computer_unconstrained_delegation import ComputerUnconstrainedDelegationCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_unconstrained_delegation(clean_neo4j):
    load_fixture(clean_neo4j, "computer_unconstrained_delegation.cypher")
    findings = run_check(ComputerUnconstrainedDelegationCheck, clean_neo4j)
    assert ComputerUnconstrainedDelegationCheck.RISK_LEVEL == "High"
    assert len(findings) == 1
    assert "S-1-5-21-TEST-1001" in findings
    assert findings["S-1-5-21-TEST-1001"] == ""
