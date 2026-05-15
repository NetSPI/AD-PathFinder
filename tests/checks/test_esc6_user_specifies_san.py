import pytest

from checks.esc6_user_specifies_san import ESC6UserSpecifiesSANCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_san_enabled_ca_with_no_sec_ext(clean_neo4j):
    load_fixture(clean_neo4j, "esc6_user_specifies_san.cypher")
    findings = run_check(ESC6UserSpecifiesSANCheck, clean_neo4j)
    assert findings, "ESC6 should fire when CA allows SAN and template lacks security extension"
    assert "NoSecExt" in str(findings)


def test_silent_when_manager_approval_required(clean_neo4j):
    load_fixture(clean_neo4j, "esc6_user_specifies_san_manager_approval.cypher")
    findings = run_check(ESC6UserSpecifiesSANCheck, clean_neo4j)
    assert not findings, "ESC6 must not fire when manager approval is required"
