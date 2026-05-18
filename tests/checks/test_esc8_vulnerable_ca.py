import pytest

from checks.esc8_vulnerable_ca import ESC8VulnerableCaCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_vulnerable_endpoint(clean_neo4j):
    load_fixture(clean_neo4j, "esc8_vulnerable_ca.cypher")
    findings = run_check(ESC8VulnerableCaCheck, clean_neo4j)
    assert ESC8VulnerableCaCheck.RISK_LEVEL == "High"
    assert len(findings) == 1
    key = "ca.test.local"
    assert key in findings
    assert isinstance(findings[key], dict) and "inline_description" in findings[key]
