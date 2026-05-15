import pytest

from checks.computers_with_escalation_path import ComputersWithEscalationPathCheck
from checks.core.constants import DataTypes
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_only_for_computers_in_escalation_cache(clean_neo4j):
    load_fixture(clean_neo4j, "computers_with_escalation_path.cypher")

    shared_cache = {
        DataTypes.ESCALATION_PATHS: {
            "S-1-5-21-TEST-1500": True,
        },
    }
    findings = run_check(ComputersWithEscalationPathCheck, clean_neo4j, shared_cache=shared_cache)

    assert "S-1-5-21-TEST-1500" in findings
    assert "S-1-5-21-TEST-1501" not in findings
