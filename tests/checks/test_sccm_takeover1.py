import pytest

from checks.sccm_takeover1 import SCCMTakeover1Check
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_mssql_relay_to_sccm_db(clean_neo4j):
    load_fixture(clean_neo4j, "sccm_takeover1.cypher")

    findings = run_check(SCCMTakeover1Check, clean_neo4j, domain_filter="TEST.LOCAL")
    assert findings, "TAKEOVER-1 should fire when MSSQL relay chain reaches SCCM site"
    assert "S-1-5-21-TEST-1700" in findings
