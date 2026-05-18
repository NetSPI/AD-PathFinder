import pytest

from checks.sccm_takeover5 import SCCMTakeover5Check
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_admin_service_relay(clean_neo4j):
    load_fixture(clean_neo4j, "sccm_takeover5.cypher")

    findings = run_check(SCCMTakeover5Check, clean_neo4j, domain_filter="TEST.LOCAL")
    assert SCCMTakeover5Check.RISK_LEVEL == "Critical"
    assert len(findings) == 1
    assert "S-1-5-21-TEST-1901" in findings
    assert isinstance(findings["S-1-5-21-TEST-1901"], str)
