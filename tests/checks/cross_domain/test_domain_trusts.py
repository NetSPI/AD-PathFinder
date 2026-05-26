import pytest

from checks.cross_domain.base import CrossDomainDependencies
from checks.cross_domain.domain_trusts import DomainTrustCheck
from tests.check_harness import load_fixture

pytestmark = pytest.mark.neo4j


def test_fires_on_domain_trust(clean_neo4j):
    load_fixture(clean_neo4j, "domain_trusts.cypher")

    deps = CrossDomainDependencies(
        conn=clean_neo4j,
        all_domains=["TEST.LOCAL", "OTHER.LOCAL"],
    )
    assert DomainTrustCheck.RISK_LEVEL == "Info"
    findings = DomainTrustCheck(deps).run()

    assert len(findings) == 1
    assert findings[0]["source_domain"] == "TEST.LOCAL"
    assert findings[0]["target_domain"] == "OTHER.LOCAL"
    assert findings[0]["sid_filtering"] is False
