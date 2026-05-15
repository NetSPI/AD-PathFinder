import pytest

from checks.asrep_roastable_admin_weak import AsrepRoastableAdminWeakCheck
from tests.check_harness import build_fake_account_analysis, load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_only_for_asrep_admin_with_weak_password(clean_neo4j):
    load_fixture(clean_neo4j, "asrep_roastable_admin_weak.cypher")

    fake = build_fake_account_analysis(
        weak_passwords=["alice", "bob"],
        user_details_mapping={
            "alice": {"isAdmin": True},
            "bob": {"isAdmin": False},
        },
    )
    findings = run_check(
        AsrepRoastableAdminWeakCheck,
        clean_neo4j,
        account_analysis=fake,
        preload_entity_sid_mappings=True,
    )

    assert "S-1-5-21-TEST-2200" in findings
    assert "S-1-5-21-TEST-2201" not in findings
