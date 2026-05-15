import pytest

from checks.bad_successor import BadSuccessorCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_default_group_with_ou_privilege(clean_neo4j):
    load_fixture(clean_neo4j, "bad_successor.cypher")

    findings = run_check(BadSuccessorCheck, clean_neo4j, domain_filter="TEST.LOCAL")
    assert findings, "bad_successor should fire when a 2025 DC exists and a default group has OU control"

    matched = [k for k in findings if "DOMAIN USERS" in k and "GENERICALL" in k]
    assert matched, f"Expected a finding mentioning DOMAIN USERS + GENERICALL, got keys: {list(findings.keys())}"
