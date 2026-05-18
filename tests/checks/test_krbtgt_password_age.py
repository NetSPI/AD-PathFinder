import pytest

from checks.krbtgt_password_age import KrbtgtPasswordAgeCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_stale_krbtgt_password(clean_neo4j):
    load_fixture(clean_neo4j, "krbtgt_password_age.cypher")

    findings = run_check(KrbtgtPasswordAgeCheck, clean_neo4j, domain_filter="TEST.LOCAL")
    assert KrbtgtPasswordAgeCheck.RISK_LEVEL == "Medium"
    assert len(findings) == 1
    assert "krbtgt" in findings
    assert isinstance(findings["krbtgt"], str) and "Last Changed On:" in findings["krbtgt"]
