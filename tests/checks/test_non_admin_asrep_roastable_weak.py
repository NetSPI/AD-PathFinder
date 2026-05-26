import pytest

from checks.non_admin_asrep_roastable_weak import NonAdminAsrepRoastableWeakCheck
from tests.check_harness import build_fake_account_analysis, load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_only_for_non_admin_asrep_with_weak_password(clean_neo4j):
    load_fixture(clean_neo4j, "non_admin_asrep_roastable_weak.cypher")

    fake = build_fake_account_analysis(
        weak_passwords=["alice", "bob"],
        user_details_mapping={
            "alice": {"isAdmin": False},
            "bob": {"isAdmin": True},
        },
    )
    findings = run_check(
        NonAdminAsrepRoastableWeakCheck,
        clean_neo4j,
        account_analysis=fake,
        preload_entity_sid_mappings=True,
    )

    assert len(findings) == 1
    assert NonAdminAsrepRoastableWeakCheck.RISK_LEVEL == "High"
    assert "S-1-5-21-TEST-2300" in findings
    assert findings["S-1-5-21-TEST-2300"] == ""
    assert "S-1-5-21-TEST-2301" not in findings
