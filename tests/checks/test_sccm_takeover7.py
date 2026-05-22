import pytest

from checks.sccm_takeover7 import SCCMTakeover7Check
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_ha_site_server_relay(clean_neo4j):
    load_fixture(clean_neo4j, "sccm_takeover7.cypher")

    findings = run_check(SCCMTakeover7Check, clean_neo4j, domain_filter="TEST.LOCAL")
    assert SCCMTakeover7Check.RISK_LEVEL == "Critical"
    assert len(findings) == 1
    assert "S-1-5-21-TEST-1601" in findings
    assert isinstance(findings["S-1-5-21-TEST-1601"], str)


def test_no_finding_when_second_site_server_disabled(clean_neo4j):
    load_fixture(clean_neo4j, "sccm_takeover7_disabled_host.cypher")

    findings = run_check(SCCMTakeover7Check, clean_neo4j, domain_filter="TEST.LOCAL")
    assert not findings, "disabled site server must not count toward the 2+ HA threshold"
