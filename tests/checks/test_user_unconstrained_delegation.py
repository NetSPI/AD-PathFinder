import pytest

from checks.user_unconstrained_delegation import UserUnconstrainedDelegationCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_unconstrained_delegation(clean_neo4j):
    load_fixture(clean_neo4j, "user_unconstrained_delegation.cypher")
    findings = run_check(UserUnconstrainedDelegationCheck, clean_neo4j)
    assert findings, "Should fire when user has unconstrained delegation"
