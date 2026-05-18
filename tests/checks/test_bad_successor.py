import pytest

from checks.bad_successor import BadSuccessorCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_default_group_with_ou_privilege(clean_neo4j):
    load_fixture(clean_neo4j, "bad_successor.cypher")

    findings = run_check(BadSuccessorCheck, clean_neo4j, domain_filter="TEST.LOCAL")
    assert BadSuccessorCheck.RISK_LEVEL == "High"
    assert len(findings) == 1

    key = list(findings.keys())[0]
    assert "DOMAIN USERS" in key and "GENERICALL" in key
    assert isinstance(findings[key], dict) and "inline_description" in findings[key]
