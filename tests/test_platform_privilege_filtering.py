import threading

from checks.core.dependencies import CheckDependencies
from checks.core.high_value import high_value_principal_sets_for_check
from checks.mssql_ntlm_relay import MSSQLNTLMRelayCheck
from checks.mssql_privilege_escalation import MSSQLPrivilegeEscalationCheck
from checks.sccm_privilege_escalation import SCCMPrivilegeEscalationCheck


class FakeNeo4jData:
    def __init__(self):
        self.conn = self
        self._hv_principal_sets_cache = {}
        self._hv_principal_sets_lock = threading.Lock()

    def get_admin_users_and_computers(self):
        return ["DA@TRAINING.LOCAL"], []

    def query(self, _cypher, parameters=None, name=None):
        return []


def _deps():
    return CheckDependencies(FakeNeo4jData())


def test_high_value_principal_sets_cached_across_checks():
    fake = FakeNeo4jData()
    calls = []
    fake.query = lambda _c, parameters=None, name=None: calls.append(name) or []
    deps = CheckDependencies(fake)

    high_value_principal_sets_for_check(
        MSSQLPrivilegeEscalationCheck(deps),
        query_name='mssql_priv_test',
    )
    high_value_principal_sets_for_check(
        SCCMPrivilegeEscalationCheck(deps),
        query_name='sccm_priv_test',
    )

    assert calls == ['mssql_priv_test']


def test_mssql_privilege_escalation_skips_high_value_start_principals():
    class StubMSSQLCheck(MSSQLPrivilegeEscalationCheck):
        def _fetch_escalation_paths(self):
            path = {
                'login_name': 'TRAINING\\lowpriv',
                'target_name': 'sysadmin',
                'target_type': 'MSSQL_ServerRole',
                'target_server': 'sql01.training.local:1433',
                'path_nodes': ['TRAINING\\lowpriv', 'sysadmin'],
                'path_edges': ['MSSQL_MemberOf'],
            }
            return {
                'S-1-5-21-TRAINING-500': {
                    'name': 'DA@TRAINING.LOCAL',
                    'principal_type': 'User',
                    'paths': [path],
                },
                'S-1-5-21-TRAINING-1101': {
                    'name': 'LOWPRIV@TRAINING.LOCAL',
                    'principal_type': 'User',
                    'paths': [path],
                },
            }

    findings = StubMSSQLCheck(_deps()).execute()

    assert 'S-1-5-21-TRAINING-500' not in findings
    assert 'S-1-5-21-TRAINING-1101' in findings


def test_sccm_privilege_escalation_skips_high_value_service_accounts():
    class StubSCCMCheck(SCCMPrivilegeEscalationCheck):
        def _fetch_sccm_paths(self):
            base_path = {
                'attack_type': 'service_account',
                'target_name': 'SQL Server Service Account',
                'target_type': 'MSSQL_Server',
                'database_name': 'CM_TRN',
                'server_name': 'sccmdb.training.local:1433',
                'path_edges': ['MSSQL_ServiceAccountFor'],
                'path_length': 1,
                'sccm_impact_db': 'CM_TRN',
                'sccm_impact_site': 'TRN',
            }
            return [
                {
                    **base_path,
                    'principal_sid': 'S-1-5-21-TRAINING-500',
                    'principal_name': 'DA@TRAINING.LOCAL',
                    'principal_type': 'User',
                },
                {
                    **base_path,
                    'principal_sid': 'S-1-5-21-TRAINING-1101',
                    'principal_name': 'LOWPRIV@TRAINING.LOCAL',
                    'principal_type': 'User',
                },
            ]

    findings = StubSCCMCheck(_deps()).execute()

    assert 'S-1-5-21-TRAINING-500' not in findings
    assert 'S-1-5-21-TRAINING-1101' in findings


def test_mssql_privilege_escalation_skips_graph_tagged_high_value_principals():
    class StubMSSQLCheck(MSSQLPrivilegeEscalationCheck):
        def query(self, _cypher, parameters=None, name=None):
            if name == "mssql_privilege_escalation_high_value_principals":
                return [{"name": "TIER0USER@TRAINING.LOCAL", "type": "User"}]
            return []

        def _fetch_escalation_paths(self):
            path = {
                'login_name': 'TRAINING\\tier0user',
                'target_name': 'sysadmin',
                'target_type': 'MSSQL_ServerRole',
                'target_server': 'sql01.training.local:1433',
                'path_nodes': ['TRAINING\\tier0user', 'sysadmin'],
                'path_edges': ['MSSQL_MemberOf'],
            }
            return {
                'S-1-5-21-TRAINING-700': {
                    'name': 'TIER0USER@TRAINING.LOCAL',
                    'principal_type': 'User',
                    'paths': [path],
                },
                'S-1-5-21-TRAINING-1101': {
                    'name': 'LOWPRIV@TRAINING.LOCAL',
                    'principal_type': 'User',
                    'paths': [path],
                },
            }

    findings = StubMSSQLCheck(_deps()).execute()

    assert 'S-1-5-21-TRAINING-700' not in findings
    assert 'S-1-5-21-TRAINING-1101' in findings


def test_sccm_privilege_escalation_skips_graph_tagged_high_value_principals():
    class StubSCCMCheck(SCCMPrivilegeEscalationCheck):
        def query(self, _cypher, parameters=None, name=None):
            if name == "sccm_privilege_escalation_high_value_principals":
                return [{"name": "TIER0USER@TRAINING.LOCAL", "type": "User"}]
            return []

        def _fetch_sccm_paths(self):
            base_path = {
                'attack_type': 'service_account',
                'target_name': 'SQL Server Service Account',
                'target_type': 'MSSQL_Server',
                'database_name': 'CM_TRN',
                'server_name': 'sccmdb.training.local:1433',
                'path_edges': ['MSSQL_ServiceAccountFor'],
                'path_length': 1,
                'sccm_impact_db': 'CM_TRN',
                'sccm_impact_site': 'TRN',
            }
            return [
                {
                    **base_path,
                    'principal_sid': 'S-1-5-21-TRAINING-700',
                    'principal_name': 'TIER0USER@TRAINING.LOCAL',
                    'principal_type': 'User',
                },
                {
                    **base_path,
                    'principal_sid': 'S-1-5-21-TRAINING-1101',
                    'principal_name': 'LOWPRIV@TRAINING.LOCAL',
                    'principal_type': 'User',
                },
            ]

    findings = StubSCCMCheck(_deps()).execute()

    assert 'S-1-5-21-TRAINING-700' not in findings
    assert 'S-1-5-21-TRAINING-1101' in findings


def test_sccm_privilege_escalation_formats_raw_sql_to_site_scope():
    check = SCCMPrivilegeEscalationCheck(_deps())
    line = check._format_path_line({
        'attack_type': 'privilege_escalation',
        'target_type': 'MSSQL_ServerRole',
        'server_name': 'sccmdb.training.local:1433',
        'path_edges': ['MSSQL_HasLogin', 'MSSQL_MemberOf'],
        'path_node_names': ['LOWPRIV@TRAINING.LOCAL', 'TRAINING\\lowpriv', 'sysadmin'],
        'sccm_impact_db': 'CM_TRN',
        'sccm_impact_site': 'TRN',
    })

    assert line == (
        "LOWPRIV -> MSSQL_HasLogin -> lowpriv -> MSSQL_MemberOf "
        "-> sysadmin | MSSQL_Database(CM_TRN) -> SCCM_AssignAllPermissions -> SCCM_Site(TRN)"
    )
    assert "can enable xp_cmdshell" not in line


def test_sccm_privilege_escalation_enriches_execute_on_host_context():
    check = SCCMPrivilegeEscalationCheck(_deps())
    line = check._format_path_line({
        'attack_type': 'privilege_escalation',
        'target_type': 'SCCM_Site',
        'path_edges': ['MSSQL_ExecuteOnHost', 'SCCM_AssignAllPermissions'],
        'path_edge_contexts': ['as SQLSVC@TRAINING.LOCAL', None],
        'path_node_names': [
            'sccmdb.training.local:1433',
            'SCCMDB.TRAINING.LOCAL',
            'SCCM_Site(TRN)',
        ],
        'sccm_impact_site': 'TRN',
    })

    assert line == (
        "sccmdb.training.local -> MSSQL_ExecuteOnHost (as SQLSVC@TRAINING.LOCAL) "
        "-> SCCMDB.TRAINING.LOCAL -> SCCM_AssignAllPermissions -> SCCM_Site(TRN)"
    )


def test_sccm_service_account_query_scopes_ad_accounts_to_domain():
    check = SCCMPrivilegeEscalationCheck.__new__(SCCMPrivilegeEscalationCheck)
    check._domain_filter = "training.local"
    captured = {}

    def capture_query(cypher, parameters=None, name=None):
        captured["cypher"] = cypher
        return []

    check.query = capture_query

    assert check._fetch_service_account_paths() == []
    assert 'serviceAccount.domain IN ["TRAINING.LOCAL", ["TRAINING.LOCAL"]]' in captured["cypher"]
    assert "OR NOT (serviceAccount:User OR serviceAccount:Computer OR serviceAccount:Group)" in captured["cypher"]


def test_sccm_coercion_prefers_matching_ad_source_only():
    check = SCCMPrivilegeEscalationCheck.__new__(SCCMPrivilegeEscalationCheck)
    paths = [
        {
            'principal_type': 'User',
            'principal_name': 'DA@TRAINING.LOCAL',
            'server_name': 'sql01.training.local:1433',
            'sccm_impact_site': 'TRN',
        },
        {
            'principal_type': 'MSSQL',
            'principal_name': 'TRAINING\\DA',
            'server_name': 'sql01.training.local',
            'sccm_impact_site': 'TRN',
        },
        {
            'principal_type': 'MSSQL',
            'principal_name': 'mssql-stub',
            'server_name': 'sql01.training.local',
            'sccm_impact_site': 'TRN',
        },
    ]

    kept = check._prefer_ad_coercion_sources(paths)

    assert [path['principal_name'] for path in kept] == ['DA@TRAINING.LOCAL', 'mssql-stub']


def test_sccm_format_principal_keeps_distinct_service_account_servers():
    check = SCCMPrivilegeEscalationCheck.__new__(SCCMPrivilegeEscalationCheck)
    base = {
        'attack_type': 'service_account',
        'principal_name': 'SQLSVC@TRAINING.LOCAL',
        'principal_type': 'User',
        'target_type': 'MSSQL_Server',
        'path_edges': ['MSSQL_ServiceAccountFor'],
        'path_length': 1,
        'sccm_impact_db': 'CM_TRN',
        'sccm_impact_site': 'TRN',
    }

    lines = check._format_principal([
        {**base, 'server_name': 'sql01.training.local:1433'},
        {**base, 'server_name': 'sql02.training.local:1433'},
    ])

    assert len(lines) == 2
    assert any("sql01.training.local" in line for line in lines)
    assert any("sql02.training.local" in line for line in lines)


def test_mssql_ntlm_relay_dedupes_equivalent_principal_formats():
    check = MSSQLNTLMRelayCheck.__new__(MSSQLNTLMRelayCheck)
    check._domain_filter = "training.local"

    principals = check._dedupe([
        "TRAINING\\DA",
        "DA@TRAINING.LOCAL",
        "OTHER\\DA",
    ])

    assert principals == ["DA@TRAINING.LOCAL", "OTHER\\DA"]


def test_mssql_ntlm_relay_does_not_collide_across_domains_sharing_netbios_prefix():
    check = MSSQLNTLMRelayCheck.__new__(MSSQLNTLMRelayCheck)
    check._domain_filter = "corp.local"

    principals = check._dedupe([
        "DA@CORP.LOCAL",
        "DA@CORP.EXAMPLE.COM",
    ])

    assert principals == ["DA@CORP.LOCAL", "DA@CORP.EXAMPLE.COM"]


def test_mssql_ntlm_relay_caps_principal_lines_per_server():
    check = MSSQLNTLMRelayCheck.__new__(MSSQLNTLMRelayCheck)

    principals = [f"USER{i}@TRAINING.LOCAL" for i in range(12)]
    desc = check._format_relay_path(
        principals,
        "SQL01.TRAINING.LOCAL",
        "SQLSVC@TRAINING.LOCAL",
        ["WEB01 (Windows Server)"],
    )

    lines = desc.split("\n")
    assert sum(1 for line in lines if "xp_dirtree" in line) == 5
    assert lines[-1] == "(+7 more principals)"
    assert "USER5@TRAINING.LOCAL" not in desc
