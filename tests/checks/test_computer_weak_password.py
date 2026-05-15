import pytest

from checks.computer_weak_password import ComputerWeakPasswordCheck
from tests.check_harness import build_fake_account_analysis, load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_only_for_computer_with_weak_password(clean_neo4j):
    load_fixture(clean_neo4j, "computer_weak_password.cypher")

    fake = build_fake_account_analysis(weak_passwords=["ws01$"])
    findings = run_check(
        ComputerWeakPasswordCheck,
        clean_neo4j,
        account_analysis=fake,
        preload_entity_sid_mappings=True,
    )

    assert "S-1-5-21-TEST-2100" in findings
    assert "S-1-5-21-TEST-2101" not in findings
