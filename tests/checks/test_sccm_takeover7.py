import pytest

from checks.sccm_takeover7 import SCCMTakeover7Check
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_ha_site_server_relay(clean_neo4j):
    load_fixture(clean_neo4j, "sccm_takeover7.cypher")

    findings = run_check(SCCMTakeover7Check, clean_neo4j, domain_filter="TEST.LOCAL")
    assert findings, "TAKEOVER-7 should fire when 2+ site servers exist and one lacks SMB signing"
    assert "S-1-5-21-TEST-1601" in findings
