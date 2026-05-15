import pytest

from checks.esc9_no_security_extension import ESC9NoSecurityExtensionCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_no_security_extension(clean_neo4j):
    load_fixture(clean_neo4j, "esc9_no_security_extension.cypher")
    findings = run_check(ESC9NoSecurityExtensionCheck, clean_neo4j)
    assert findings, "ESC9 should fire on template without security extension"
    assert "NoSecExt" in str(findings)


def test_silent_when_authentication_disabled(clean_neo4j):
    load_fixture(clean_neo4j, "esc9_no_security_extension_auth_disabled.cypher")
    findings = run_check(ESC9NoSecurityExtensionCheck, clean_neo4j)
    assert not findings, "ESC9 must not fire when authentication is disabled on the template"
