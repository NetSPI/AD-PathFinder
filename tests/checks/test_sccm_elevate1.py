import pytest

from checks.sccm_elevate1 import SCCMElevate1Check
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_smb_relay_to_sccm_role_holder(clean_neo4j):
    load_fixture(clean_neo4j, "sccm_elevate1.cypher")

    findings = run_check(SCCMElevate1Check, clean_neo4j, domain_filter="TEST.LOCAL")
    assert SCCMElevate1Check.RISK_LEVEL == "High"
    assert len(findings) == 1
    assert "S-1-5-21-TEST-2100" in findings
    assert isinstance(findings["S-1-5-21-TEST-2100"], str)
