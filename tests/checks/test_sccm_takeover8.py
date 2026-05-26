import pytest

from checks.sccm_takeover8 import SCCMTakeover8Check
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_ldap_relay_via_webclient(clean_neo4j):
    load_fixture(clean_neo4j, "sccm_takeover8.cypher")

    findings = run_check(SCCMTakeover8Check, clean_neo4j, domain_filter="TEST.LOCAL")
    assert SCCMTakeover8Check.RISK_LEVEL == "Critical"
    assert len(findings) == 1
    assert "S-1-5-21-TEST-2000" in findings
    assert isinstance(findings["S-1-5-21-TEST-2000"], str)
