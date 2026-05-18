import pytest

from checks.core.constants import DataTypes
from checks.users_with_escalation_path import UsersWithEscalationPathCheck
from tests.check_harness import build_fake_account_analysis, load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_only_for_non_admin_with_escalation_path(clean_neo4j):
    load_fixture(clean_neo4j, "users_with_escalation_path.cypher")

    fake = build_fake_account_analysis(
        user_details_mapping={
            "alice": {"isAdmin": False},
            "bob": {"isAdmin": True},
        },
    )
    shared_cache = {
        DataTypes.ESCALATION_PATHS: {
            "S-1-5-21-TEST-3100": True,
            "S-1-5-21-TEST-3101": True,
        },
    }
    findings = run_check(
        UsersWithEscalationPathCheck,
        clean_neo4j,
        shared_cache=shared_cache,
        account_analysis=fake,
        preload_entity_sid_mappings=True,
    )

    assert len(findings) == 1
    assert UsersWithEscalationPathCheck.RISK_LEVEL == "Critical"
    assert "S-1-5-21-TEST-3100" in findings
    assert findings["S-1-5-21-TEST-3100"] == ""
    assert "S-1-5-21-TEST-3101" not in findings
