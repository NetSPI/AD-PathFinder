import pytest

from checks.computer_constrained_delegation import ComputerConstrainedDelegationCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_constrained_delegation(clean_neo4j):
    load_fixture(clean_neo4j, "computer_constrained_delegation.cypher")
    findings = run_check(ComputerConstrainedDelegationCheck, clean_neo4j)
    assert findings, "Should fire when computer has constrained delegation configured"
    assert "MSSQLSvc" in str(findings)
