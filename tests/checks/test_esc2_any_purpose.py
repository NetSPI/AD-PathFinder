import pytest

from checks.esc2_any_purpose import ESC2AnyPurposeCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_any_purpose_eku(clean_neo4j):
    load_fixture(clean_neo4j, "esc2_any_purpose.cypher")
    findings = run_check(ESC2AnyPurposeCheck, clean_neo4j)
    assert ESC2AnyPurposeCheck.RISK_LEVEL == "High"
    assert len(findings) == 1
    key = "AnyPurpose (TEST-CA on ca.test.local)"
    assert key in findings
    assert isinstance(findings[key], str)
