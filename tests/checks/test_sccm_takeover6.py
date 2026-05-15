import pytest

from checks.sccm_takeover6 import SCCMTakeover6Check
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_smb_relay_to_sms_provider(clean_neo4j):
    load_fixture(clean_neo4j, "sccm_takeover6.cypher")

    findings = run_check(SCCMTakeover6Check, clean_neo4j, domain_filter="TEST.LOCAL")
    assert findings, "TAKEOVER-6 should fire when SMS Provider has SMB signing disabled"
    assert "S-1-5-21-TEST-1200" in findings
