import pytest

from checks.non_admin_computer_rights import NonAdminComputerRightsCheck
from tests.check_harness import build_fake_account_analysis, load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_only_for_non_admin_with_admin_rights(clean_neo4j):
    load_fixture(clean_neo4j, "non_admin_computer_rights.cypher")

    fake = build_fake_account_analysis(
        user_details_mapping={
            "alice": {"isAdmin": False},
            "bob": {"isAdmin": True},
        },
    )
    findings = run_check(
        NonAdminComputerRightsCheck,
        clean_neo4j,
        domain_filter="TEST.LOCAL",
        account_analysis=fake,
        preload_entity_sid_mappings=True,
    )

    assert "S-1-5-21-TEST-3000" in findings
    detail = str(findings["S-1-5-21-TEST-3000"])
    assert "SRV01.TEST.LOCAL" in detail
    assert "S-1-5-21-TEST-3001" not in findings
