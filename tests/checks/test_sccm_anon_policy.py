import pytest

from checks.sccm_anon_policy import SCCMAnonPolicyCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_management_point(clean_neo4j):
    load_fixture(clean_neo4j, "sccm_anon_policy.cypher")

    findings = run_check(SCCMAnonPolicyCheck, clean_neo4j, domain_filter="TEST.LOCAL")
    assert SCCMAnonPolicyCheck.RISK_LEVEL == "Medium"
    assert len(findings) == 1
    assert "S-1-5-21-TEST-1300" in findings
    assert isinstance(findings["S-1-5-21-TEST-1300"], str)
    assert "client certificate requirement not observed" in findings["S-1-5-21-TEST-1300"]
    assert "http://mgmtpt.test.local/ccm_system/request" in findings["S-1-5-21-TEST-1300"]
    assert "source:" not in findings["S-1-5-21-TEST-1300"]
