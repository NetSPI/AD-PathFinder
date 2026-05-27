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
    desc = findings["VictimV1 (TEST-CA on ca.test.local)"]
    assert "via paired ESC3 agent 'Agent'" in desc
    assert "enrollable by DOMAIN USERS" in desc


def test_does_not_fire_when_no_agent_template_on_same_ca(clean_neo4j):
    load_fixture(clean_neo4j, "esc3_victim_no_agent.cypher")
    findings = run_check(ESC3VictimTemplateCheck, clean_neo4j)
    assert findings == {}


def test_does_not_fire_when_agent_and_victim_acls_are_disjoint(clean_neo4j):
    load_fixture(clean_neo4j, "esc3_victim_disjoint_acl.cypher")
    findings = run_check(ESC3VictimTemplateCheck, clean_neo4j)
    assert findings == {}


def test_lists_only_contributing_agent_enrollers(clean_neo4j):
    load_fixture(clean_neo4j, "esc3_victim_mixed_acl.cypher")
    findings = run_check(ESC3VictimTemplateCheck, clean_neo4j)
    key = "MachineVictim (TEST-CA-4 on ca4.test.local)"
    assert key in findings
    desc = findings[key]
    assert "DOMAIN COMPUTERS (via paired ESC3 agent 'Agent'" in desc
    assert "AUTHENTICATED USERS" in desc
    assert "DOMAIN USERS" not in desc
