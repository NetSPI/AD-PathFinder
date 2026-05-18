import pytest

from checks.admin_weak_password import AdminWeakPasswordCheck
from tests.check_harness import build_fake_account_analysis, load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_only_for_admin_with_weak_password(clean_neo4j):
    load_fixture(clean_neo4j, "admin_weak_password.cypher")

    fake = build_fake_account_analysis(
        weak_passwords=["alice", "bob"],
        user_details_mapping={
            "alice": {"isAdmin": True},
            "bob": {"isAdmin": False},
            "carol": {"isAdmin": True},
        },
    )
    findings = run_check(
        AdminWeakPasswordCheck,
        clean_neo4j,
        account_analysis=fake,
        preload_entity_sid_mappings=True,
    )

    assert len(findings) == 1
    assert AdminWeakPasswordCheck.RISK_LEVEL == "Critical"
    assert "S-1-5-21-TEST-1500" in findings
    assert findings["S-1-5-21-TEST-1500"] == ""
    # bob has a weak password but isn't admin; carol is admin but password isn't weak.
    assert "S-1-5-21-TEST-1501" not in findings
    assert "S-1-5-21-TEST-1502" not in findings
