from checks.core import Check, check

_INTERNAL_MSSQL_OBJECTS = {
    '##MS_POLICYSIGNINGCERTIFICATE##',
    '##MS_POLICYEVENTPROCESSINGLOGIN##',
    '##MS_POLICYTSSQLEXECUTIONLOGIN##',
    '##MS_AGENTSINGETLOGLOGIN##',
    '##MS_AGENTSIGNINGCERTIFICATE##',
}

_HIGH_VALUE_SERVER_ROLES = {
    'SYSADMIN', 'SECURITYADMIN', 'SERVERADMIN', 'PROCESSADMIN',
    'SETUPADMIN', 'BULKADMIN', 'DISKADMIN', 'DBCREATOR',
}

_HIGH_VALUE_DB_ROLES = {
    'DB_OWNER', 'DB_SECURITYADMIN', 'DB_ACCESSADMIN', 'DB_BACKUPOPERATOR',
    'DB_DDLADMIN', 'DB_DATAWRITER', 'DB_DATAREADER',
}

_SQL2022_ROLES = {
    '##MS_DEFINITIONREADER##', '##MS_SERVERPERFORMANCESTATEREADER##',
    '##MSS_SERVERPERFORMANCESTATEREADER##', '##MS_DATABASECONNECTOR##',
    '##MS_DATABASEMANAGER##', '##MS_LOGINMANAGER##', '##MS_SECURITYDEFINITIONREADER##',
}

_HIGH_VALUE_PERMISSIONS = {
    'CONTROL SERVER', 'IMPERSONATE ANY LOGIN', 'ALTER ANY LOGIN',
    'ALTER ANY SERVER ROLE', 'ALTER ANY CREDENTIAL', 'ALTER ANY EVENT SESSION',
    'ADMINISTER BULK OPERATIONS', 'CONTROL', 'ALTER ANY DATABASE ROLE',
    'ALTER ANY USER', 'IMPERSONATE', 'TAKE OWNERSHIP', 'VIEW DATABASE STATE',
}

_VALUABLE_NODE_TYPES = {
    'MSSQL_ServerRole', 'MSSQL_Login', 'MSSQL_DatabaseRole',
    'MSSQL_DatabaseUser', 'MSSQL_Server', 'Computer',
}

_SYSADMIN_SUBORDINATES = {
    'SECURITYADMIN', 'SERVERADMIN', 'PROCESSADMIN', 'SETUPADMIN',
    'BULKADMIN', 'DISKADMIN', 'DBCREATOR',
}

@check(risk="High", category="MSSQL Privilege Escalation", entity="user", data=[], requires=["mssql"])
class MSSQLPrivilegeEscalationCheck(Check):

    def execute(self):
        admin_users, admin_computers = self.neo4j_data.get_admin_users_and_computers()
        admin_users_set = set(u.upper() for u in admin_users) if admin_users else set()
        admin_computers_set = set(c.upper() for c in admin_computers) if admin_computers else set()

        paths_data = self._fetch_escalation_paths()
        if not paths_data:
            return {}

        results = {}
        for entity_sid, entity_info in paths_data.items():
            entity_name = (entity_info.get('name') or '').upper()
            if entity_name in admin_users_set or entity_name in admin_computers_set:
                continue
            if not entity_info.get('paths'):
                continue

            server_groups = {}
            for path_info in entity_info['paths']:
                if not self._is_valuable_target(path_info):
                    continue

                target_name = (path_info.get('target_name') or '').upper()
                server = self._normalize_server_name(path_info.get('target_server') or '')
                login = path_info.get('login_name') or ''
                step_count = len(path_info.get('path_edges') or [])

                if not server:
                    server = self._normalize_server_name(path_info.get('sql_server') or '')

                group_key = (server.upper(), login.upper())
                if group_key not in server_groups:
                    server_groups[group_key] = {}

                targets = server_groups[group_key]
                if target_name not in targets or step_count < targets[target_name][0]:
                    targets[target_name] = (step_count, path_info)

            all_lines = []
            for (server_key, login_key), targets in sorted(server_groups.items()):
                has_sysadmin = 'SYSADMIN' in targets

                filtered_targets = {}
                for tname, (steps, pinfo) in targets.items():
                    if has_sysadmin and tname in _SYSADMIN_SUBORDINATES:
                        continue
                    filtered_targets[tname] = (steps, pinfo)

                if not filtered_targets:
                    continue

                server_display = server_key.lower() if server_key else 'unknown'

                sorted_targets = sorted(
                    filtered_targets.items(),
                    key=lambda x: (0 if x[0] == 'SYSADMIN' else 1, x[1][0], x[0])
                )

                for _tname, (_steps, pinfo) in sorted_targets:
                    chain = self._build_chain(pinfo, server_display)
                    if chain:
                        all_lines.append(chain)

            if all_lines:
                results[entity_sid] = self.finding("\n".join(all_lines))

        return results

    def _fetch_escalation_paths(self):
        domain_cond = self._domain_condition("principal")

        rows = self.query(f"""
            MATCH (startLogin:MSSQL_Login)<-[:MSSQL_HasLogin]-(principal)
            WHERE (principal:User OR principal:Computer){domain_cond}

            MATCH (target)
            WHERE (
                (target:MSSQL_ServerRole AND toUpper(target.name) IN [
                    'SYSADMIN', 'SECURITYADMIN', 'SERVERADMIN', 'PROCESSADMIN',
                    'SETUPADMIN', 'BULKADMIN', 'DISKADMIN', 'DBCREATOR'
                ])
                OR (target:MSSQL_Login AND target.explicitPermissions IS NOT NULL
                    AND ANY(perm IN target.explicitPermissions WHERE toUpper(perm) IN [
                        'CONTROL SERVER', 'ALTER ANY LOGIN', 'ALTER ANY SERVER ROLE',
                        'IMPERSONATE ANY LOGIN', 'ALTER ANY CREDENTIAL', 'AUTHENTICATE SERVER'
                    ]))
                OR (target:MSSQL_DatabaseRole AND toUpper(target.name) IN [
                    'DB_OWNER', 'DB_SECURITYADMIN', 'DB_ACCESSADMIN'
                ])
                OR (target:MSSQL_DatabaseUser AND target.explicitPermissions IS NOT NULL
                    AND ANY(perm IN target.explicitPermissions WHERE toUpper(perm) IN [
                        'CONTROL', 'ALTER', 'ALTER ANY DATABASE ROLE',
                        'ALTER ANY USER', 'IMPERSONATE', 'TAKE OWNERSHIP'
                    ]))
                OR (target:Computer)
              )
            AND target <> startLogin

            WITH principal, startLogin, target
            MATCH p = shortestPath((startLogin)-[rels*1..5]->(target))
            WHERE ALL(rel IN rels WHERE rel.traversable = true)

            OPTIONAL MATCH (db:MSSQL_Database)-[:MSSQL_Contains]->(target)
            OPTIONAL MATCH (server:MSSQL_Server {{name: target.SQLServer}})

            WITH principal, startLogin, target, p, rels, db, server,
                 [node in nodes(p) | coalesce(node.name, '')] as pathNodes,
                 [rel in rels | type(rel)] as pathEdges,
                 length(p) as pathLength,
                 CASE WHEN principal:Computer THEN 'Computer' ELSE 'User' END as principalType

            WITH principal, startLogin, target, p, rels, db, server, pathNodes, pathEdges, pathLength, principalType,
                 CASE
                     WHEN target:MSSQL_ServerRole THEN 'MSSQL_ServerRole'
                     WHEN target:MSSQL_DatabaseRole THEN 'MSSQL_DatabaseRole'
                     WHEN target:MSSQL_Login THEN 'MSSQL_Login'
                     WHEN target:MSSQL_DatabaseUser THEN 'MSSQL_DatabaseUser'
                     WHEN target:MSSQL_Server THEN 'MSSQL_Server'
                     WHEN target:MSSQL_Database THEN 'MSSQL_Database'
                     WHEN target:Computer THEN 'Computer'
                     WHEN target:MSSQL_Base THEN 'MSSQL'
                     WHEN target:SCCM_Base THEN 'SCCM'
                     ELSE coalesce(
                         head([label IN labels(target)
                               WHERE NOT label IN ['Base', 'MSSQL_Base', 'SCCM_Base', 'OpenGraph_Stub', 'ADLocalGroup', 'LocalGroup']
                               AND NOT label STARTS WITH 'Tag_']),
                         'Unknown'
                     )
                 END as targetTypeResolved

            RETURN principal.objectid as userSid,
                   principal.name as userName,
                   principalType,
                   startLogin.name as loginName,
                   startLogin.SQLServer as sqlServer,
                   target.name as targetName,
                   targetTypeResolved as targetType,
                   target.SQLServer as targetServer,
                   target.explicitPermissions as targetPermissions,
                   db.name as databaseName,
                   db.isTrustworthy as isTrustworthy,
                   db.hasGuestEnabled as hasGuestEnabled,
                   server.xpCmdShellEnabled as xpCmdShellEnabled,
                   pathNodes,
                   pathEdges,
                   pathLength
            ORDER BY userName, pathLength
        """, name="mssql_privilege_escalation_paths")

        paths_by_user = {}
        for row in rows:
            user_sid = row.get('userSid')
            if not user_sid:
                continue

            if user_sid not in paths_by_user:
                paths_by_user[user_sid] = {
                    'name': row.get('userName') or '',
                    'principal_type': row.get('principalType') or '',
                    'paths': []
                }

            paths_by_user[user_sid]['paths'].append({
                'login_name': row.get('loginName') or '',
                'sql_server': row.get('sqlServer') or '',
                'target_name': row.get('targetName') or '',
                'target_type': row.get('targetType') or '',
                'target_server': row.get('targetServer') or '',
                'target_permissions': row.get('targetPermissions') or [],
                'database_name': row.get('databaseName') or '',
                'is_trustworthy': row.get('isTrustworthy', False),
                'has_guest_enabled': row.get('hasGuestEnabled', False),
                'xp_cmdshell_enabled': row.get('xpCmdShellEnabled', False),
                'path_nodes': row.get('pathNodes') or [],
                'path_edges': row.get('pathEdges') or [],
                'path_length': row.get('pathLength') or 0,
            })

        return paths_by_user

    def _normalize_server_name(self, server_name):
        if not server_name:
            return ''
        return server_name.split(':')[0]

    def _build_chain(self, path_info, server_display=''):
        path_edges = path_info.get('path_edges', [])
        path_nodes = path_info.get('path_nodes', [])
        target_type = path_info.get('target_type', '')
        target_permissions = path_info.get('target_permissions', [])
        database_name = path_info.get('database_name', '')

        if not path_edges or not path_nodes:
            return ""

        cleaned = [self._clean_node_name(n) for n in path_nodes]

        has_oscmd_tail = (
            target_type == 'Computer'
            and len(path_edges) >= 2
            and path_edges[-2] == 'MSSQL_ControlServer'
            and path_edges[-1] == 'MSSQL_ExecuteOnHost'
        )

        parts = [cleaned[0]]

        for i, edge in enumerate(path_edges):
            next_name = cleaned[i + 1] if i + 1 < len(cleaned) else '?'
            parts.append(edge)
            is_final_host = has_oscmd_tail and i == len(path_edges) - 1
            parts.append(next_name.lower() if is_final_host else self._display_node(next_name))

        chain = " -> ".join(parts)

        if has_oscmd_tail:
            return chain

        if target_type in ('MSSQL_DatabaseRole', 'MSSQL_DatabaseUser') and database_name:
            chain = chain + f" ({database_name})"
        elif target_type == 'MSSQL_Login':
            perms = [p for p in target_permissions if p and p.upper() in _HIGH_VALUE_PERMISSIONS]
            if perms:
                chain = chain + f" ({', '.join(perms)})"
        if server_display:
            chain = chain + f" on {server_display}"

        return chain

    def _display_node(self, name):
        upper = name.upper()
        if upper in _HIGH_VALUE_SERVER_ROLES or upper in _HIGH_VALUE_DB_ROLES:
            return name.lower()
        return name

    def _is_valuable_target(self, path_info):
        target_name = (path_info.get('target_name') or '').upper()
        target_type = path_info.get('target_type') or ''
        target_permissions = path_info.get('target_permissions') or []

        if target_name in _INTERNAL_MSSQL_OBJECTS:
            return False
        if target_name in _HIGH_VALUE_SERVER_ROLES:
            return True
        if target_name in _HIGH_VALUE_DB_ROLES:
            return True
        if target_name in _SQL2022_ROLES:
            return True
        if target_permissions and any(perm and perm.upper() in _HIGH_VALUE_PERMISSIONS for perm in target_permissions):
            return True
        if target_type in _VALUABLE_NODE_TYPES:
            return True
        return False

    def _clean_node_name(self, node_name):
        if not node_name:
            return "?"
        if '\\' in node_name:
            node_name = node_name.split('\\')[-1]
        node_name = self._normalize_server_name(node_name)
        return node_name
