import pytest

from checks.esc3_enrollment_agent import ESC3EnrollmentAgentCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_enrollment_agent_template(clean_neo4j):
    load_fixture(clean_neo4j, "esc3_enrollment_agent.cypher")
    findings = run_check(ESC3EnrollmentAgentCheck, clean_neo4j)
    assert findings, "ESC3 should fire on DOMAIN USERS with Enroll on a Cert Request Agent EKU template"
    assert "EnrollAgent" in str(findings)


def test_silent_when_manager_approval_required(clean_neo4j):
    load_fixture(clean_neo4j, "esc3_enrollment_agent_manager_approval.cypher")
    findings = run_check(ESC3EnrollmentAgentCheck, clean_neo4j)
    assert not findings
