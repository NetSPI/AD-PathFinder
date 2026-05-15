import pytest

from checks.core.constants import DataTypes
from checks.smb_signing_with_path import WeakComputerConfigCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_only_for_smb_disabled_in_escalation_cache(clean_neo4j):
    load_fixture(clean_neo4j, "smb_signing_with_path.cypher")

    shared_cache = {
        DataTypes.ESCALATION_PATHS: {
            "S-1-5-21-TEST-1600": True,
        },
    }
    findings = run_check(WeakComputerConfigCheck, clean_neo4j, shared_cache=shared_cache)

    assert "S-1-5-21-TEST-1600" in findings
    assert "SMB Signing Disabled" in findings["S-1-5-21-TEST-1600"]
    assert "S-1-5-21-TEST-1601" not in findings
