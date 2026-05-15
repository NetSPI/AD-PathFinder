import pytest

from checks.smb_signing import SMBSigningCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_smb_signing_disabled(clean_neo4j):
    load_fixture(clean_neo4j, "smb_signing.cypher")
    findings = run_check(SMBSigningCheck, clean_neo4j)
    assert findings, "Should fire when computer has SMB signing disabled"
    assert "Windows 10" in str(findings)
