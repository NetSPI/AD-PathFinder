import pytest

from checks.account_shared_password import AccountSharedPasswordCheck
from tests.check_harness import build_fake_account_analysis, load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_only_for_user_with_shared_password(clean_neo4j):
    load_fixture(clean_neo4j, "account_shared_password.cypher")

    fake = build_fake_account_analysis(users_in_shared_accounts={"alice"})
    findings = run_check(
        AccountSharedPasswordCheck,
        clean_neo4j,
        account_analysis=fake,
        preload_entity_sid_mappings=True,
    )

    assert len(findings) == 1
    assert AccountSharedPasswordCheck.RISK_LEVEL == "Medium"
    assert "S-1-5-21-TEST-2800" in findings
    assert findings["S-1-5-21-TEST-2800"] == ""
    assert "S-1-5-21-TEST-2801" not in findings
