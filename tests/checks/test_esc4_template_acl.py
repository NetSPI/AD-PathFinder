import pytest

from checks.esc4_template_acl import ESC4TemplateACLCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_template_write_acl(clean_neo4j):
    load_fixture(clean_neo4j, "esc4_template_acl.cypher")
    findings = run_check(ESC4TemplateACLCheck, clean_neo4j)
    assert findings, "ESC4 should fire when low-priv group has write ACL on template"
    assert "WritableTemplate" in str(findings)
