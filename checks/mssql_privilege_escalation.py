from checks.core import Check, check
from checks.core.high_value import high_value_principal_sets_for_check, is_high_value_principal
from checks.core.mssql_common import (
    MSSQL_ABUSE_EDGES,
    linked_server_target_resolution,
    primary_label_expr,
    sql_login_holder_parameters,
    sql_login_report_holder_expr,
    sql_login_report_holder_filter,
)

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
    'MSSQL_DatabaseUser',
}

_SYSADMIN_SUBORDINATES = {
    'SECURITYADMIN', 'SERVERADMIN', 'PROCESSADMIN', 'SETUPADMIN',
    'BULKADMIN', 'DISKADMIN', 'DBCREATOR',
}

@check(risk="High", category="MSSQL Privilege Escalation", entity="user", data=[], requires=["mssql"],
       display="shared_graph_paths")
class MSSQLPrivilegeEscalationCheck(Check):

    def execute(self):
        high_value_users, high_value_computers, high_value_groups = (
            high_value_principal_sets_for_check(
                self,
                query_name="mssql_privilege_escalation_high_value_principals",
            )
        )

        paths_data = self._fetch_escalation_paths()
        if not paths_data:
            return {}

        results = {}
        for entity_sid, entity_info in paths_data.items():
            if is_high_value_principal(
                entity_info.get('name') or '',
                entity_info.get('principal_type') or '',
                high_value_users,
                high_value_computers,
                high_value_groups,
            ):
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
        holder_domain_cond = self._domain_condition("holder")
        candidate_domain_cond = self._domain_condition("candidatePrincipal")
        member_domain_cond = self._domain_condition("memberPrincipal")

        rows = self.query(f"""
            MATCH (holder)-[:MSSQL_HasLogin]->(startLogin:MSSQL_Login)
            WHERE holder:User OR holder:Computer OR holder:Group

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
              )
            AND target <> startLogin

            WITH holder, startLogin, target,
                 {sql_login_report_holder_expr()} AS reportHolder
            {sql_login_report_holder_filter(holder_domain_cond, candidate_domain_cond)}
            MATCH p = shortestPath((startLogin)-[rels*1..5]->(target))
            WHERE ALL(rel IN rels WHERE type(rel) IN $_abuse_edges)

            OPTIONAL MATCH (db:MSSQL_Database)-[:MSSQL_Contains]->(target)
            OPTIONAL MATCH memberPath = (memberPrincipal)-[:MemberOf*1..6]->(holder)
            WHERE holder:Group AND NOT reportHolder
              AND (memberPrincipal:User OR memberPrincipal:Computer){member_domain_cond}

            WITH CASE
                     WHEN reportHolder OR holder:User OR holder:Computer THEN holder
                     ELSE memberPrincipal
                 END AS principal,
                 holder, startLogin, target, p, rels, db, reportHolder, memberPath
            WHERE principal IS NOT NULL
              AND (reportHolder OR principal:User OR principal:Computer){domain_cond}
              AND (NOT principal:Computer OR coalesce(principal.enabled, true) = true)

            WITH principal, holder, startLogin, target, p, rels, db, reportHolder, memberPath,
                 CASE
                     WHEN reportHolder THEN [split(coalesce(holder.name, ''), '@')[0]] + [node IN nodes(p) | coalesce(node.name, '')]
                     WHEN holder:Group AND memberPath IS NOT NULL
                         THEN {self._ad_member_path_node_names_expr('nodes(memberPath)')} + [node IN nodes(p) | coalesce(node.name, '')]
                     ELSE [node in nodes(p) | coalesce(node.name, '')]
                 END as pathNodes,
                 CASE
                     WHEN reportHolder THEN ['MSSQL_HasLogin'] + [rel in rels | type(rel)]
                     WHEN holder:Group AND memberPath IS NOT NULL
                         THEN [rel IN relationships(memberPath) | type(rel)] + ['MSSQL_HasLogin'] + [rel in rels | type(rel)]
                     ELSE [rel in rels | type(rel)]
                 END as pathEdges,
                 CASE
                     WHEN reportHolder THEN length(p) + 1
                     WHEN holder:Group AND memberPath IS NOT NULL THEN length(memberPath) + length(p) + 1
                     ELSE length(p)
                 END as pathLength,
                 CASE
                     WHEN reportHolder THEN 'Group'
                     WHEN principal:Computer THEN 'Computer'
                     ELSE 'User'
                 END as principalType

            WITH principal, holder, startLogin, target, p, rels, db, reportHolder,
                 pathNodes, pathEdges, pathLength, principalType,
                 CASE
                     WHEN target:MSSQL_ServerRole THEN 'MSSQL_ServerRole'
                     WHEN target:MSSQL_DatabaseRole THEN 'MSSQL_DatabaseRole'
                     WHEN target:MSSQL_Login THEN 'MSSQL_Login'
                     WHEN target:MSSQL_DatabaseUser THEN 'MSSQL_DatabaseUser'
                     WHEN target:MSSQL_Database THEN 'MSSQL_Database'
                     WHEN target:MSSQL_Base THEN 'MSSQL'
                     WHEN target:SCCM_Base THEN 'SCCM'
                     ELSE coalesce({primary_label_expr('target')}, 'Unknown')
                 END as targetTypeResolved

            RETURN CASE WHEN reportHolder THEN holder.objectid ELSE principal.objectid END as userSid,
                   CASE WHEN reportHolder THEN holder.name ELSE principal.name END as userName,
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
                   pathNodes,
                   pathEdges,
                   pathLength
            ORDER BY userName, pathLength
        """, parameters={
            "_abuse_edges": MSSQL_ABUSE_EDGES,
            **sql_login_holder_parameters(),
        }, name="mssql_privilege_escalation_paths")

        rows = list(rows) + self._fetch_linked_server_paths()

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
                'path_nodes': row.get('pathNodes') or [],
                'path_edges': row.get('pathEdges') or [],
                'path_length': row.get('pathLength') or 0,
            })

        return paths_by_user

    def _fetch_linked_server_paths(self):
        domain_cond = self._domain_condition("principal")
        holder_domain_cond = self._domain_condition("holder")
        candidate_domain_cond = self._domain_condition("candidatePrincipal")
        member_domain_cond = self._domain_condition("memberPrincipal")

        rows = self.query(f"""
            MATCH (holder)-[:MSSQL_HasLogin]->(startLogin:MSSQL_Login)
            WHERE holder:User OR holder:Computer OR holder:Group

            WITH holder, startLogin,
                 {sql_login_report_holder_expr()} AS reportHolder
            {sql_login_report_holder_filter(holder_domain_cond, candidate_domain_cond)}
            MATCH (startLogin)-[:MSSQL_Connect]->(srvA:MSSQL_Server)
            MATCH (srvA)-[:MSSQL_LinkedAsAdmin]->(srvB_stub:MSSQL_Server)

            MATCH (srvB:MSSQL_Server)-[:MSSQL_Contains]->(target:MSSQL_ServerRole)
            WHERE {linked_server_target_resolution('srvB', 'srvB_stub')}
              AND toUpper(target.name) IN [
                  'SYSADMIN', 'SECURITYADMIN', 'SERVERADMIN', 'PROCESSADMIN',
                  'SETUPADMIN', 'BULKADMIN', 'DISKADMIN', 'DBCREATOR'
              ]
            OPTIONAL MATCH memberPath = (memberPrincipal)-[:MemberOf*1..6]->(holder)
            WHERE holder:Group AND NOT reportHolder
              AND (memberPrincipal:User OR memberPrincipal:Computer){member_domain_cond}
            WITH CASE
                     WHEN reportHolder OR holder:User OR holder:Computer THEN holder
                     ELSE memberPrincipal
                 END AS principal,
                 holder, startLogin, reportHolder, srvA, srvB, target, memberPath
            WHERE principal IS NOT NULL
              AND (reportHolder OR principal:User OR principal:Computer){domain_cond}
              AND (NOT principal:Computer OR coalesce(principal.enabled, true) = true)
            RETURN DISTINCT
                   CASE WHEN reportHolder THEN holder.objectid ELSE principal.objectid END as userSid,
                   CASE WHEN reportHolder THEN holder.name ELSE principal.name END as userName,
                   CASE
                       WHEN reportHolder THEN 'Group'
                       WHEN principal:Computer THEN 'Computer'
                       ELSE 'User'
                   END as principalType,
                   startLogin.name as loginName,
                   startLogin.SQLServer as sqlServer,
                   target.name as targetName,
                   'MSSQL_ServerRole' as targetType,
                   srvB.name as targetServer,
                   CASE
                       WHEN reportHolder THEN [split(coalesce(holder.name, ''), '@')[0], startLogin.name, srvA.name, srvB.name, target.name]
                       WHEN holder:Group AND memberPath IS NOT NULL
                           THEN {self._ad_member_path_node_names_expr('nodes(memberPath)')} + [startLogin.name, srvA.name, srvB.name, target.name]
                       ELSE [startLogin.name, srvA.name, srvB.name, target.name]
                   END as pathNodes,
                   CASE
                       WHEN reportHolder THEN ['MSSQL_HasLogin', 'MSSQL_Connect', 'MSSQL_LinkedAsAdmin', 'MSSQL_Contains']
                       WHEN holder:Group AND memberPath IS NOT NULL
                           THEN [rel IN relationships(memberPath) | type(rel)] + ['MSSQL_HasLogin', 'MSSQL_Connect', 'MSSQL_LinkedAsAdmin', 'MSSQL_Contains']
                       ELSE ['MSSQL_Connect', 'MSSQL_LinkedAsAdmin', 'MSSQL_Contains']
                   END as pathEdges,
                   CASE
                       WHEN reportHolder THEN 4
                       WHEN holder:Group AND memberPath IS NOT NULL THEN length(memberPath) + 4
                       ELSE 3
                   END as pathLength
        """, parameters=sql_login_holder_parameters(), name="mssql_priv_esc_linked_server")
        return list(rows)

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
        if server_display and cleaned:
            cleaned[-1] = self._target_display_name(cleaned[-1], target_type, server_display)

        parts = [cleaned[0]]

        for i, edge in enumerate(path_edges):
            next_name = cleaned[i + 1] if i + 1 < len(cleaned) else '?'
            parts.append(edge)
            parts.append(self._display_node(next_name))

        chain = " -> ".join(parts)

        if target_type in ('MSSQL_DatabaseRole', 'MSSQL_DatabaseUser') and database_name:
            chain = chain + f" ({database_name})"
        elif target_type == 'MSSQL_Login':
            perms = [p for p in target_permissions if p and p.upper() in _HIGH_VALUE_PERMISSIONS]
            if perms:
                chain = chain + f" ({', '.join(perms)})"

        return chain

    def _target_display_name(self, name, target_type, server_display):
        if target_type in ('MSSQL_ServerRole', 'MSSQL_Login') and '@' not in name:
            return f"{name}@{server_display}"
        return name

    def _display_node(self, name):
        role_name, sep, scope = name.partition('@')
        if role_name.upper() in _HIGH_VALUE_SERVER_ROLES or role_name.upper() in _HIGH_VALUE_DB_ROLES:
            return f"{role_name.lower()}{sep}{scope}"
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

    def _ad_member_path_node_names_expr(self, nodes_expr):
        return f"[node IN {nodes_expr} | split(coalesce(node.name, node.objectid, ''), '@')[0]]"
