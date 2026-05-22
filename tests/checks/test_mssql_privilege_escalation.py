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


def test_fires_on_linked_server_path_with_case_mismatched_bridge(clean_neo4j):
    load_fixture(clean_neo4j, "mssql_privilege_escalation_linked_server.cypher")

    findings = run_check(MSSQLPrivilegeEscalationCheck, clean_neo4j, domain_filter="TEST.LOCAL")
    user_sid = "S-1-5-21-TEST-3201"
    assert user_sid in findings
    detail = findings[user_sid]
    assert "MSSQL_LinkedAsAdmin" in detail
    assert "sysadmin" in detail.lower()
    assert "sccmdb.test.local" in detail


def test_fires_on_group_owned_linked_server_path(clean_neo4j):
    load_fixture(clean_neo4j, "mssql_privilege_escalation_linked_server.cypher")

    findings = run_check(MSSQLPrivilegeEscalationCheck, clean_neo4j, domain_filter="TEST.LOCAL")
    user_sid = "S-1-5-21-TEST-3202"
    assert user_sid in findings
    detail = findings[user_sid]
    assert "linked-group" in detail
    assert "MSSQL_LinkedAsAdmin" in detail
    assert "sysadmin" in detail.lower()


def test_common_group_owned_linked_server_reports_group_not_members(clean_neo4j):
    load_fixture(clean_neo4j, "mssql_privilege_escalation_linked_server.cypher")

    findings = run_check(MSSQLPrivilegeEscalationCheck, clean_neo4j, domain_filter="TEST.LOCAL")
    assert "S-1-5-21-TEST-513" in findings
    assert "S-1-5-21-TEST-3203" not in findings
    detail = findings["S-1-5-21-TEST-513"]
    assert "DOMAIN USERS" in detail
    assert "DOMAIN USERS -> MSSQL_HasLogin -> Domain Users -> MSSQL_Connect" in detail
    assert "MSSQL_LinkedAsAdmin" in detail
    assert "sysadmin" in detail.lower()


def test_fires_on_linked_server_with_sid_based_stub(clean_neo4j):
    load_fixture(clean_neo4j, "mssql_priv_esc_linked_server_sid.cypher")

    findings = run_check(MSSQLPrivilegeEscalationCheck, clean_neo4j, domain_filter="TEST.LOCAL")
    user_sid = "S-1-5-21-TEST-3301"
    assert user_sid in findings
    detail = findings[user_sid]
    assert "MSSQL_LinkedAsAdmin" in detail
    assert "sysadmin" in detail.lower()
    assert "sccmdb.test.local" in detail


def test_fires_when_login_owns_high_value_server_role(clean_neo4j):
    load_fixture(clean_neo4j, "mssql_priv_esc_owns_server_role.cypher")

    findings = run_check(MSSQLPrivilegeEscalationCheck, clean_neo4j, domain_filter="TEST.LOCAL")
    user_sid = "S-1-5-21-TEST-3601"
    assert user_sid in findings
    detail = findings[user_sid]
    assert "MSSQL_Owns" in detail
    assert "sysadmin" in detail.lower()


def test_does_not_fire_when_stub_name_only_substring_matches_sqlservername(clean_neo4j):
    load_fixture(clean_neo4j, "mssql_priv_esc_linked_server_overmatch.cypher")

    findings = run_check(MSSQLPrivilegeEscalationCheck, clean_neo4j, domain_filter="TEST.LOCAL")
    assert findings == {}


def test_fires_on_group_owned_login_through_nested_memberof_depth_6(clean_neo4j):
    load_fixture(clean_neo4j, "mssql_priv_esc_group_owned_login.cypher")

    findings = run_check(MSSQLPrivilegeEscalationCheck, clean_neo4j, domain_filter="TEST.LOCAL")
    user_sid = "S-1-5-21-TEST-3401"
    assert user_sid in findings
    detail = findings[user_sid]
    assert "group-login" in detail
    assert "NESTEDUSER -> MemberOf -> G1 -> MemberOf -> G2" in detail
    assert "SQL OWNERS -> MSSQL_HasLogin -> group-login" in detail
    assert "@TEST.LOCAL" not in detail
    assert "sysadmin" in detail.lower()
