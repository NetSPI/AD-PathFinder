import pytest

from checks.sccm_anon_policy import SCCMAnonPolicyCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_management_point(clean_neo4j):
    load_fixture(clean_neo4j, "sccm_anon_policy.cypher")

    findings = run_check(SCCMAnonPolicyCheck, clean_neo4j, domain_filter="TEST.LOCAL")
    assert findings, "Should flag management point for anonymous policy retrieval review"
    assert "S-1-5-21-TEST-1300" in findings
    assert "ccm_system_altauth/request" in str(findings["S-1-5-21-TEST-1300"])
