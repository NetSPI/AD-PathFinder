import pytest

from checks.sccm_takeover4 import SCCMTakeover4Check
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_cas_child_relay(clean_neo4j):
    load_fixture(clean_neo4j, "sccm_takeover4.cypher")

    findings = run_check(SCCMTakeover4Check, clean_neo4j, domain_filter="TEST.LOCAL")
    assert findings, "TAKEOVER-4 should fire when child site server has SMB signing disabled"
    assert "S-1-5-21-TEST-1501" in findings
