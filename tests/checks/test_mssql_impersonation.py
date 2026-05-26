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


def test_enumerates_all_branches_at_non_source_fan_out(clean_neo4j):
    load_fixture(clean_neo4j, "mssql_impersonation_branched.cypher")
    findings = run_check(MSSQLImpersonationCheck, clean_neo4j, domain_filter="TEST.LOCAL")
    assert "S-1-5-21-TEST-2002" in findings
    chain_text = findings["S-1-5-21-TEST-2002"]
    # Both branches of mid must be reachable via the lowpriv-rooted chain,
    # not just via the mid-rooted chain.
    assert "TEST\\lowpriv -> EXECUTE AS TEST\\mid -> EXECUTE AS aaa" in chain_text
    assert "TEST\\lowpriv -> EXECUTE AS TEST\\mid -> EXECUTE AS bbb" in chain_text
