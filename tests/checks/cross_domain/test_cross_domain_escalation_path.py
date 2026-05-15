import pytest

from checks.cross_domain.base import CrossDomainDependencies
from checks.cross_domain.cross_domain_escalation_path import CrossDomainEscalationPathCheck
from tests.check_harness import load_fixture

pytestmark = pytest.mark.neo4j


def test_fires_on_cross_domain_user_path_to_da(clean_neo4j):
    load_fixture(clean_neo4j, "cross_domain_escalation_path.cypher")

    deps = CrossDomainDependencies(
        conn=clean_neo4j,
        all_domains=["TEST.LOCAL", "OTHER.LOCAL"],
        relationship_pattern="MemberOf|AdminTo|GenericAll",
    )
    findings = CrossDomainEscalationPathCheck(deps).run()

    assert findings
    match = next(f for f in findings if f["source_sid"] == "S-1-5-21-TEST-4000")
    assert match["target_domain"] == "OTHER.LOCAL"
    assert match["target_type"] == "Domain Admin"
    assert match["fullPath"], "fullPath should not be empty"
