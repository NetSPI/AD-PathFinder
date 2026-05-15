import pytest

from checks.kerberoastable_admin_weak import KerberoastableAdminWeakCheck
from tests.check_harness import build_fake_account_analysis, load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_only_for_kerberoastable_admin_with_weak_password(clean_neo4j):
    load_fixture(clean_neo4j, "kerberoastable_admin_weak.cypher")

    fake = build_fake_account_analysis(
        weak_passwords=["alice", "bob"],
        user_details_mapping={
            "alice": {"isAdmin": True},
            "bob": {"isAdmin": False},
        },
    )
    findings = run_check(
        KerberoastableAdminWeakCheck,
        clean_neo4j,
        account_analysis=fake,
        preload_entity_sid_mappings=True,
    )

    assert "S-1-5-21-TEST-2400" in findings
    assert "S-1-5-21-TEST-2401" not in findings
