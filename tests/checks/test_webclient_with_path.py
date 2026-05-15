import pytest

from checks.core.constants import DataTypes
from checks.webclient_with_path import WebClientComputerCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_only_for_computers_in_escalation_cache(clean_neo4j):
    load_fixture(clean_neo4j, "webclient_with_path.cypher")

    shared_cache = {
        DataTypes.ESCALATION_PATHS: {
            "S-1-5-21-TEST-1400": True,
        },
    }
    findings = run_check(WebClientComputerCheck, clean_neo4j, shared_cache=shared_cache)

    assert "S-1-5-21-TEST-1400" in findings
    assert "S-1-5-21-TEST-1401" not in findings
