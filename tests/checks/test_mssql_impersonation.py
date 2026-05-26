import pytest

from checks.mssql_impersonation import MSSQLImpersonationCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_login_impersonation_chain(clean_neo4j):
    load_fixture(clean_neo4j, "mssql_impersonation.cypher")
    findings = run_check(MSSQLImpersonationCheck, clean_neo4j, domain_filter="TEST.LOCAL")
    assert MSSQLImpersonationCheck.RISK_LEVEL == "Medium"
    assert len(findings) == 1
    assert "S-1-5-21-TEST-2001" in findings
    assert isinstance(findings["S-1-5-21-TEST-2001"], str)
    assert "EXECUTE AS" in findings["S-1-5-21-TEST-2001"]
