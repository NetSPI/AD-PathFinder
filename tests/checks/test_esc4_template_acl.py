import pytest

from checks.esc4_template_acl import ESC4TemplateACLCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_template_write_acl(clean_neo4j):
    load_fixture(clean_neo4j, "esc4_template_acl.cypher")
    findings = run_check(ESC4TemplateACLCheck, clean_neo4j)
    assert ESC4TemplateACLCheck.RISK_LEVEL == "Critical"
    assert len(findings) == 1
    key = "WritableTemplate (TEST-CA on ca.test.local)"
    assert key in findings
    assert isinstance(findings[key], str)
