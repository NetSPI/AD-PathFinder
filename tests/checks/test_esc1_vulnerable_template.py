import pytest

from checks.esc1_vulnerable_template import ESC1VulnerableTemplateCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_enrollee_supplies_subject(clean_neo4j):
    load_fixture(clean_neo4j, "esc1_vulnerable_template.cypher")
    findings = run_check(ESC1VulnerableTemplateCheck, clean_neo4j)
    assert ESC1VulnerableTemplateCheck.RISK_LEVEL == "Critical"
    assert len(findings) == 1
    key = "VulnTemplate (TEST-CA on ca.test.local)"
    assert key in findings
    assert isinstance(findings[key], str)


def test_silent_when_manager_approval_required(clean_neo4j):
    load_fixture(clean_neo4j, "esc1_vulnerable_template_manager_approval.cypher")
    findings = run_check(ESC1VulnerableTemplateCheck, clean_neo4j)
    assert not findings, "ESC1 must not fire when manager approval is required"
