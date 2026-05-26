import pytest

from checks.esc3_victim_template import ESC3VictimTemplateCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_for_v1_and_cosign_victims_but_skips_plain_v2(clean_neo4j):
    load_fixture(clean_neo4j, "esc3_victim_template.cypher")
    findings = run_check(ESC3VictimTemplateCheck, clean_neo4j)
    assert ESC3VictimTemplateCheck.RISK_LEVEL == "High"
    assert len(findings) == 2
    assert "VictimV1 (TEST-CA on ca.test.local)" in findings
    assert "VictimCoSign (TEST-CA on ca.test.local)" in findings
    assert "NotVictim (TEST-CA on ca.test.local)" not in findings
    assert "via paired ESC3 agent cert" in findings["VictimV1 (TEST-CA on ca.test.local)"]


def test_does_not_fire_when_no_agent_template_on_same_ca(clean_neo4j):
    load_fixture(clean_neo4j, "esc3_victim_no_agent.cypher")
    findings = run_check(ESC3VictimTemplateCheck, clean_neo4j)
    assert findings == {}
