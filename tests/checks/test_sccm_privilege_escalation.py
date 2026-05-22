import pytest

from checks.core import DisplayTypes
from checks.sccm_privilege_escalation import SCCMPrivilegeEscalationCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def _run_sccm_check(conn):
    load_fixture(conn, "sccm_privilege_escalation.cypher")
    return run_check(SCCMPrivilegeEscalationCheck, conn, domain_filter="TEST.LOCAL")


def test_fires_on_ad_group_to_sccm_site(clean_neo4j):
    findings = _run_sccm_check(clean_neo4j)

    user_sid = "S-1-5-21-TEST-100"
    assert SCCMPrivilegeEscalationCheck.RISK_LEVEL == "Critical"
    assert user_sid in findings
    detail = findings[user_sid]
    assert "SCCM_IsMappedTo" in detail
    assert "SCCM_AllPermissions" in detail
    assert "P01" in detail
    assert "Base" not in detail


def test_fires_on_nested_ad_group_to_sccm_site_depth_6(clean_neo4j):
    findings = _run_sccm_check(clean_neo4j)

    user_sid = "S-1-5-21-TEST-101"
    assert user_sid in findings
    detail = findings[user_sid]
    assert "NESTED -> MemberOf -> N1 -> MemberOf -> N2" in detail
    assert "@TEST.LOCAL" not in detail
    assert "SCCM_AllPermissions" in detail


def test_fires_on_priv_esc_to_sccm_server_sysadmin(clean_neo4j):
    findings = _run_sccm_check(clean_neo4j)

    user_sid = "S-1-5-21-TEST-102"
    assert user_sid in findings
    detail = findings[user_sid]
    assert "sysadmin" in detail.lower()
    assert "MSSQL_Database(CM_P01) -> SCCM_AssignAllPermissions -> SCCM_Site(P01)" in detail


def test_fires_on_priv_esc_to_sccm_database_role(clean_neo4j):
    findings = _run_sccm_check(clean_neo4j)

    user_sid = "S-1-5-21-TEST-103"
    assert user_sid in findings
    detail = findings[user_sid]
    assert "db_owner@CM_P01" in detail
    assert "MSSQL_Database(CM_P01) -> SCCM_AssignAllPermissions -> SCCM_Site(P01)" in detail


def test_fires_on_linked_server_to_sccm_target(clean_neo4j):
    findings = _run_sccm_check(clean_neo4j)

    user_sid = "S-1-5-21-TEST-104"
    assert user_sid in findings
    detail = findings[user_sid]
    assert "MSSQL_LinkedAsAdmin" in detail
    assert "MSSQL_Database(CM_P01) -> SCCM_AssignAllPermissions -> SCCM_Site(P01)" in detail


def test_fires_on_linked_execute_host_to_sccm_site(clean_neo4j):
    findings = _run_sccm_check(clean_neo4j)

    user_sid = "S-1-5-21-TEST-109"
    assert user_sid in findings
    detail = findings[user_sid]
    assert "EXECCHAIN -> MSSQL_HasLogin -> execchain -> MSSQL_ExecuteAs -> ReportSvc" in detail
    assert "MSSQL_LinkedAsAdmin" in detail
    assert "MSSQL_ExecuteOnHost (as SQLSVC@TEST.LOCAL)" in detail
    assert detail.count("MSSQL_ExecuteOnHost") == 1
    assert "SCCMSQL.TEST.LOCAL -> SCCM_AssignAllPermissions -> SCCM_Site(P01)" in detail


def test_fires_on_group_owned_linked_server_to_sccm_target(clean_neo4j):
    findings = _run_sccm_check(clean_neo4j)

    user_sid = "S-1-5-21-TEST-107"
    assert user_sid in findings
    detail = findings[user_sid]
    assert "GROUPLINKED -> MemberOf -> LINKED SQL USERS -> MSSQL_HasLogin" in detail
    assert "linked-group" in detail
    assert "GROUPLINKED@TEST.LOCAL" not in detail
    assert "LINKED SQL USERS@TEST.LOCAL" not in detail
    assert "MSSQL_LinkedAsAdmin" in detail
    assert "MSSQL_Database(CM_P01) -> SCCM_AssignAllPermissions -> SCCM_Site(P01)" in detail


def test_common_group_owned_linked_server_to_sccm_reports_group_not_members(clean_neo4j):
    findings = _run_sccm_check(clean_neo4j)

    assert SCCMPrivilegeEscalationCheck.DISPLAY_TYPE == DisplayTypes.SHARED_GRAPH_PATHS
    assert "S-1-5-21-TEST-513" in findings
    assert "S-1-5-21-TEST-108" not in findings
    detail = findings["S-1-5-21-TEST-513"]
    assert "DOMAIN USERS" in detail
    assert "DOMAIN USERS -> MSSQL_HasLogin -> Domain Users -> MSSQL_Connect" in detail
    assert "MSSQL_LinkedAsAdmin" in detail
    assert "MSSQL_Database(CM_P01) -> SCCM_AssignAllPermissions -> SCCM_Site(P01)" in detail


def test_fires_on_alter_any_login_to_sccm_server(clean_neo4j):
    findings = _run_sccm_check(clean_neo4j)

    user_sid = "S-1-5-21-TEST-105"
    assert user_sid in findings
    detail = findings[user_sid]
    assert "MSSQL_AlterAnyLogin" in detail
    assert "MSSQL_Database(CM_P01) -> SCCM_AssignAllPermissions -> SCCM_Site(P01)" in detail


def test_fires_on_admin_user_with_full_administrator_role(clean_neo4j):
    findings = _run_sccm_check(clean_neo4j)

    user_sid = "S-1-5-21-TEST-106"
    assert user_sid in findings
    detail = findings[user_sid]
    assert "SCCM_IsAssigned" in detail
    assert "Full Administrator" in detail


def test_no_finding_for_connect_only_login_on_sccm_server(clean_neo4j):
    findings = _run_sccm_check(clean_neo4j)
    assert "S-1-5-21-TEST-200" not in findings


def test_no_finding_for_linked_execute_host_on_disabled_sccm_computer(clean_neo4j):
    findings = _run_sccm_check(clean_neo4j)
    assert "S-1-5-21-TEST-203" not in findings


def test_no_finding_for_linked_execute_host_without_remote_admin(clean_neo4j):
    findings = _run_sccm_check(clean_neo4j)
    assert "S-1-5-21-TEST-204" not in findings


def test_no_finding_for_non_admin_group_admin_user(clean_neo4j):
    findings = _run_sccm_check(clean_neo4j)
    assert "S-1-5-21-TEST-201" not in findings


def test_no_cross_forest_sccm_target_when_domain_filter_set(clean_neo4j):
    findings = _run_sccm_check(clean_neo4j)
    assert "S-1-5-21-TEST-202" not in findings


def test_linked_server_target_does_not_overmatch_sibling_host(clean_neo4j):
    load_fixture(clean_neo4j, "sccm_priv_esc_linked_server_name_overmatch.cypher")

    findings = run_check(SCCMPrivilegeEscalationCheck, clean_neo4j, domain_filter="TEST.LOCAL")
    user_sid = "S-1-5-21-TEST-310"
    assert user_sid in findings
    detail = findings[user_sid]
    assert "cmsql.test.local" in detail
    assert "CM_P10" in detail
    assert "cmsql-dr" not in detail
    assert "CM_DR" not in detail


def test_linked_server_empty_target_stub_resolves_to_nothing(clean_neo4j):
    load_fixture(clean_neo4j, "sccm_priv_esc_linked_server_empty_stub.cypher")

    findings = run_check(SCCMPrivilegeEscalationCheck, clean_neo4j, domain_filter="TEST.LOCAL")
    assert "S-1-5-21-TEST-311" not in findings


def test_linked_server_shared_host_sid_bridges_to_no_instance(clean_neo4j):
    load_fixture(clean_neo4j, "sccm_priv_esc_linked_server_shared_host_sid.cypher")

    findings = run_check(SCCMPrivilegeEscalationCheck, clean_neo4j, domain_filter="TEST.LOCAL")
    assert "S-1-5-21-TEST-312" not in findings
