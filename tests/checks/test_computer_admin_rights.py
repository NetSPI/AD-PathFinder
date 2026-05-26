import pytest

from checks.computer_admin_rights import ComputerAdminRightsCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_computer_with_admin_to_another(clean_neo4j):
    load_fixture(clean_neo4j, "computer_admin_rights.cypher")

    findings = run_check(ComputerAdminRightsCheck, clean_neo4j, domain_filter="TEST.LOCAL")
    assert ComputerAdminRightsCheck.RISK_LEVEL == "High"
    assert len(findings) == 1

    source_sid = "S-1-5-21-TEST-5001"
    assert source_sid in findings
    finding = findings[source_sid]
    assert isinstance(finding, (str, dict))
    assert "SRV01.TEST.LOCAL" in str(finding)
