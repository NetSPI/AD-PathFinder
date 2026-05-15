import pytest

from checks.sccm_takeover2 import SCCMTakeover2Check
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_smb_relay_to_site_db(clean_neo4j):
    load_fixture(clean_neo4j, "sccm_takeover2.cypher")

    findings = run_check(SCCMTakeover2Check, clean_neo4j, domain_filter="TEST.LOCAL")
    assert findings, "TAKEOVER-2 should fire when SMB relay reaches site database host"
    assert "S-1-5-21-TEST-1800" in findings
