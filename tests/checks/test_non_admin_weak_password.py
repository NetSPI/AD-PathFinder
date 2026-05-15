import pytest

from checks.non_admin_weak_password import NonAdminWeakPasswordCheck
from tests.check_harness import build_fake_account_analysis, load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_only_for_non_admin_with_weak_password(clean_neo4j):
    load_fixture(clean_neo4j, "non_admin_weak_password.cypher")

    fake = build_fake_account_analysis(
        weak_passwords=["alice", "bob"],
        user_details_mapping={
            "alice": {"isAdmin": False},
            "bob": {"isAdmin": True},
        },
    )
    findings = run_check(
        NonAdminWeakPasswordCheck,
        clean_neo4j,
        account_analysis=fake,
        preload_entity_sid_mappings=True,
    )

    assert "S-1-5-21-TEST-2000" in findings
    assert "S-1-5-21-TEST-2001" not in findings
