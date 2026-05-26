import pytest

from checks.smb_signing import SMBSigningCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_smb_signing_disabled(clean_neo4j):
    load_fixture(clean_neo4j, "smb_signing.cypher")
    findings = run_check(SMBSigningCheck, clean_neo4j)
    assert SMBSigningCheck.RISK_LEVEL == "Medium"
    assert len(findings) == 1
    sid = "S-1-5-21-TEST-1001"
    assert sid in findings
    assert isinstance(findings[sid], dict) and "inline_description" in findings[sid]
