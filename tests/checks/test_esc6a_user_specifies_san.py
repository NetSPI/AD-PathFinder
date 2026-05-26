import pytest

from checks.esc6a_user_specifies_san import ESC6aUserSpecifiesSANCheck
from checks.esc6_user_specifies_san import ESC6UserSpecifiesSANCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_editf_ca_even_when_template_has_security_extension(clean_neo4j):
    load_fixture(clean_neo4j, "esc6a_user_specifies_san.cypher")
    findings = run_check(ESC6aUserSpecifiesSANCheck, clean_neo4j)
    assert ESC6aUserSpecifiesSANCheck.RISK_LEVEL == "Critical"
    assert len(findings) == 1
    key = "PrePatch (TEST-CA on ca.test.local)"
    assert key in findings


def test_post_patch_check_does_not_fire_on_pre_patch_only_fixture(clean_neo4j):
    load_fixture(clean_neo4j, "esc6a_user_specifies_san.cypher")
    findings = run_check(ESC6UserSpecifiesSANCheck, clean_neo4j)
    assert findings == {}
