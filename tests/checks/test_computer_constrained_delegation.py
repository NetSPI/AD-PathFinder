import pytest

from checks.computer_constrained_delegation import ComputerConstrainedDelegationCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_constrained_delegation(clean_neo4j):
    load_fixture(clean_neo4j, "computer_constrained_delegation.cypher")
    findings = run_check(ComputerConstrainedDelegationCheck, clean_neo4j)
    assert ComputerConstrainedDelegationCheck.RISK_LEVEL == "Medium"
    assert len(findings) == 1
    sid = "S-1-5-21-TEST-1001"
    assert sid in findings
    assert isinstance(findings[sid], str) and "Constrained Delegation:" in findings[sid]
