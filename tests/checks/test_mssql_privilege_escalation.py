import pytest

from checks.mssql_privilege_escalation import MSSQLPrivilegeEscalationCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_login_to_sysadmin_path(clean_neo4j):
    load_fixture(clean_neo4j, "mssql_privilege_escalation.cypher")

    findings = run_check(MSSQLPrivilegeEscalationCheck, clean_neo4j, domain_filter="TEST.LOCAL")
    assert MSSQLPrivilegeEscalationCheck.RISK_LEVEL == "High"
    assert len(findings) == 1

    user_sid = "S-1-5-21-TEST-3101"
    assert user_sid in findings
    detail = findings[user_sid]
    assert isinstance(detail, str)
    assert "sysadmin" in detail.lower()
    assert "sql01.test.local" in detail
