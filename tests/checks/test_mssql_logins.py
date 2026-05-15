import pytest

from checks.mssql_logins import MSSQLLoginsCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_non_admin_user_with_db_control(clean_neo4j):
    load_fixture(clean_neo4j, "mssql_logins.cypher")
    findings = run_check(MSSQLLoginsCheck, clean_neo4j, domain_filter="TEST.LOCAL")
    assert findings, "mssql_logins should detect non-admin user with MSSQL login"
    assert "S-1-5-21-TEST-2201" in findings
    detail = findings["S-1-5-21-TEST-2201"]
    assert "sql01.test.local:1433" in detail
    assert "AppDB" in detail
