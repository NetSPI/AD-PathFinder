import pytest

from checks.esc7_ca_permissions import ESC7CAPermissionsCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_manage_ca_permission(clean_neo4j):
    load_fixture(clean_neo4j, "esc7_ca_permissions.cypher")
    findings = run_check(ESC7CAPermissionsCheck, clean_neo4j)
    assert ESC7CAPermissionsCheck.RISK_LEVEL == "Critical"
    assert len(findings) == 1
    key = "TEST-CA (ca.test.local)"
    assert key in findings
    assert isinstance(findings[key], str)
