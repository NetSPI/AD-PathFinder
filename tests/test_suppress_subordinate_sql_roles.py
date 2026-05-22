from checks.core.dependencies import CheckDependencies
from checks.sccm_privilege_escalation import SCCMPrivilegeEscalationCheck


class FakeNeo4jData:
    high_value_users_cache = []
    high_value_computers_cache = []

    def __init__(self):
        self.conn = self

    def get_admin_users_and_computers(self):
        return [], []

    def query(self, _cypher, parameters=None, name=None):
        return []


def _check():
    return SCCMPrivilegeEscalationCheck(CheckDependencies(FakeNeo4jData()))


def _server_role(name, server='sql01.training.local:1433', site=''):
    return {
        'target_type': 'MSSQL_ServerRole',
        'target_name': name,
        'server_name': server,
        'database_name': '',
        'sccm_impact_site': site,
    }


def _db_role(name, server='sql01.training.local:1433', database='master'):
    return {
        'target_type': 'MSSQL_DatabaseRole',
        'target_name': name,
        'server_name': server,
        'database_name': database,
        'sccm_impact_site': '',
    }


def test_sysadmin_suppresses_subordinate_server_role_in_same_scope():
    paths = [_server_role('sysadmin'), _server_role('securityadmin')]

    filtered = _check()._suppress_subordinate_sql_roles(paths)

    assert [p['target_name'] for p in filtered] == ['sysadmin']


def test_sysadmin_absent_keeps_subordinate_server_role():
    paths = [_server_role('securityadmin'), _server_role('serveradmin')]

    filtered = _check()._suppress_subordinate_sql_roles(paths)

    assert [p['target_name'] for p in filtered] == ['securityadmin', 'serveradmin']


def test_db_owner_suppresses_subordinate_database_role_in_same_scope():
    paths = [_db_role('db_owner'), _db_role('db_securityadmin')]

    filtered = _check()._suppress_subordinate_sql_roles(paths)

    assert [p['target_name'] for p in filtered] == ['db_owner']


def test_sysadmin_on_one_server_does_not_suppress_subordinate_on_another():
    paths = [
        _server_role('sysadmin', server='sql01.training.local:1433'),
        _server_role('securityadmin', server='sql02.training.local:1433'),
    ]

    filtered = _check()._suppress_subordinate_sql_roles(paths)

    assert [(p['target_name'], p['server_name']) for p in filtered] == [
        ('sysadmin', 'sql01.training.local:1433'),
        ('securityadmin', 'sql02.training.local:1433'),
    ]


def test_non_subordinate_role_is_kept_even_when_sysadmin_present():
    paths = [_server_role('sysadmin'), _server_role('processadmin')]

    filtered = _check()._suppress_subordinate_sql_roles(paths)

    assert [p['target_name'] for p in filtered] == ['sysadmin', 'processadmin']


def test_role_key_strips_scope_suffix_and_normalises_case():
    paths = [
        _server_role('SYSADMIN@SQL01'),
        _server_role('SecurityAdmin@SQL01'),
    ]

    filtered = _check()._suppress_subordinate_sql_roles(paths)

    assert [p['target_name'] for p in filtered] == ['SYSADMIN@SQL01']


def test_sccm_impact_site_isolates_suppression_scope():
    paths = [
        _server_role('sysadmin', site='PRI'),
        _server_role('securityadmin', site='SEC'),
    ]

    filtered = _check()._suppress_subordinate_sql_roles(paths)

    assert [(p['target_name'], p['sccm_impact_site']) for p in filtered] == [
        ('sysadmin', 'PRI'),
        ('securityadmin', 'SEC'),
    ]
