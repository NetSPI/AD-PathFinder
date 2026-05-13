from checks.core import Check, check
from checks.core.platform_mixins import MSSQLDomainMixin


@check(risk="Critical", category="SCCM Database Compromise", entity="user", data=[], requires=["mssql"])
class MSSQLSCCMCheck(MSSQLDomainMixin, Check):

    def execute(self):
        admin_users, admin_computers = self.neo4j_data.get_admin_users_and_computers()
        admin_users_set = set(u.upper() for u in admin_users) if admin_users else set()
        admin_computers_set = set(c.upper() for c in admin_computers) if admin_computers else set()

        sccm_paths = self._fetch_sccm_paths()
        if not sccm_paths:
            return {}

        by_principal = {}

        for path in sccm_paths:
            sid = path.get('principal_sid')
            if not sid:
                continue

            name = (path.get('principal_name') or '').upper()
            ptype = path.get('principal_type') or ''

            attack_type = path.get('attack_type') or ''

            if attack_type == 'privilege_escalation':
                if ptype == 'User' and name in admin_users_set:
                    continue
                if ptype == 'Computer' and name in admin_computers_set:
                    continue

            if sid not in by_principal:
                by_principal[sid] = {'name': name, 'type': ptype, 'paths': []}
            by_principal[sid]['paths'].append(path)

        results = {}
        for sid, info in by_principal.items():
            lines = self._format_principal(info)
            if lines:
                results[sid] = self.finding("\n".join(lines))

        return results

    def _fetch_sccm_paths(self):
        all_paths = []
        all_paths.extend(self._fetch_priv_esc_paths())
        all_paths.extend(self._fetch_coercion_paths())
        all_paths.extend(self._fetch_service_account_paths())
        return all_paths

    def _fetch_priv_esc_paths(self):
        domain_cond = self._domain_condition("principal")

        rows = self.query(f"""
            MATCH (principal)-[:MSSQL_HasLogin]->(startLogin:MSSQL_Login)
            WHERE (principal:User OR principal:Computer){domain_cond}

            WITH principal, startLogin
            MATCH (sccmDb:MSSQL_Database)
            WHERE sccmDb.isTrustworthy = true
            AND (sccmDb.name CONTAINS 'CM_' OR sccmDb.name CONTAINS 'SMS' OR sccmDb.name CONTAINS 'SCCM')

            WITH principal, startLogin, sccmDb
            MATCH (target)
            WHERE (
              (target:MSSQL_DatabaseRole
               AND target.name IN ['db_owner', 'db_securityadmin', 'db_accessadmin', 'db_ddladmin']
               AND (sccmDb)-[:MSSQL_Contains]->(target))
              OR (target:MSSQL_DatabaseUser
                  AND target.explicitPermissions IS NOT NULL
                  AND ('CONTROL' IN target.explicitPermissions OR 'ALTER DATABASE' IN target.explicitPermissions)
                  AND (sccmDb)-[:MSSQL_Contains]->(target))
              OR (target = sccmDb)
              OR (target:SCCM_Site AND (sccmDb)-[:SCCM_AssignAllPermissions]->(target))
            )

            WITH principal, startLogin, target, sccmDb
            MATCH p = shortestPath((startLogin)-[rels*1..5]->(target))
            WHERE ALL(rel IN rels WHERE rel.traversable = true)
            AND length(p) > 0

            WITH principal, startLogin, target, sccmDb, p, nodes(p) as pathNodes,
                 [rel in rels | type(rel)] as pathEdges,
                 length(p) as pathLength,
                 CASE WHEN 'SCCM_Site' IN labels(target) THEN 'SCCM_Site' ELSE labels(target)[0] END as targetType

            WITH principal, startLogin, target, sccmDb, p, pathNodes, pathEdges, pathLength, targetType
            WHERE ANY(node IN pathNodes WHERE
              (node = sccmDb) OR
              (node:MSSQL_DatabaseUser AND node.database = sccmDb.name) OR
              (node:MSSQL_DatabaseRole AND node.database = sccmDb.name)
            )

            OPTIONAL MATCH (server:MSSQL_Server {{name: sccmDb.SQLServer}})

            RETURN DISTINCT
                   principal.objectid as principalSid,
                   principal.name as principalName,
                   CASE WHEN principal:Computer THEN 'Computer' ELSE 'User' END as principalType,
                   target.name as targetName,
                   targetType,
                   target.explicitPermissions as targetPermissions,
                   sccmDb.name as databaseName,
                   sccmDb.SQLServer as serverName,
                   server.xpCmdShellEnabled as xpCmdShellEnabled,
                   pathEdges,
                   pathLength,
                   [node IN pathNodes | coalesce(node.name, [l IN labels(node) WHERE l <> 'SCCM_Base' AND l <> 'Base'][0], labels(node)[0])] as pathNodeNames
        """, name="sccm_privilege_escalation_paths")

        paths = []
        for row in rows:
            paths.append({
                'attack_type': 'privilege_escalation',
                'principal_sid': row.get('principalSid'),
                'principal_name': row.get('principalName') or '',
                'principal_type': row.get('principalType') or '',
                'target_name': row.get('targetName') or '',
                'target_type': row.get('targetType') or '',
                'target_permissions': row.get('targetPermissions') or [],
                'database_name': row.get('databaseName') or '',
                'server_name': row.get('serverName') or '',
                'xp_cmdshell_enabled': row.get('xpCmdShellEnabled', False),
                'path_edges': row.get('pathEdges') or [],
                'path_length': row.get('pathLength') or 0,
                'path_node_names': row.get('pathNodeNames') or [],
            })
        return paths

    def _fetch_coercion_paths(self):
        source_domain_cond = self._domain_condition("source")
        source_filter = (f"\nWHERE true{source_domain_cond}") if source_domain_cond else ""

        rows = self.query(f"""
            MATCH (source)-[:CoerceAndRelayToMSSQL]->(login:MSSQL_Login){source_filter}

            WITH source, login
            MATCH (sccmDb:MSSQL_Database {{SQLServer: login.SQLServer}})
            WHERE sccmDb.isTrustworthy = true
            AND (sccmDb.name CONTAINS 'CM_' OR sccmDb.name CONTAINS 'SMS' OR sccmDb.name CONTAINS 'SCCM')

            OPTIONAL MATCH (server:MSSQL_Server {{name: login.SQLServer}})

            RETURN DISTINCT
                   labels(source)[0] as sourceType,
                   source.name as sourceName,
                   source.objectid as sourceSid,
                   login.name as loginName,
                   login.SQLServer as sqlServer,
                   server.xpCmdShellEnabled as xpCmdShellEnabled,
                   collect(DISTINCT sccmDb.name) as sccmDatabases
        """, name="sccm_coercion_paths")

        paths = []
        for row in rows:
            paths.append({
                'attack_type': 'coercion',
                'principal_sid': row.get('sourceSid'),
                'principal_name': row.get('sourceName') or '',
                'principal_type': row.get('sourceType') or '',
                'target_name': row.get('loginName') or '',
                'target_type': 'MSSQL_Login',
                'database_name': ', '.join(row.get('sccmDatabases') or []),
                'server_name': row.get('sqlServer') or '',
                'xp_cmdshell_enabled': row.get('xpCmdShellEnabled', False),
                'path_edges': ['CoerceAndRelayToMSSQL'],
                'path_length': 1,
            })
        return paths

    def _fetch_service_account_paths(self):
        sccm_server_filter = self._server_domain_condition("sccmDb.SQLServer")

        rows = self.query(f"""
            MATCH (sccmDb:MSSQL_Database)
            WHERE sccmDb.isTrustworthy = true
            AND (sccmDb.name CONTAINS 'CM_' OR sccmDb.name CONTAINS 'SMS' OR sccmDb.name CONTAINS 'SCCM'){sccm_server_filter}

            WITH DISTINCT sccmDb.SQLServer as sqlServer, collect(DISTINCT sccmDb.name) as sccmDatabases

            MATCH (serviceAccount)-[:MSSQL_ServiceAccountFor]->(server:MSSQL_Server {{name: sqlServer}})

            RETURN DISTINCT
                   labels(serviceAccount)[0] as serviceAccountType,
                   serviceAccount.name as serviceAccountName,
                   serviceAccount.objectid as serviceAccountSid,
                   sqlServer,
                   sccmDatabases,
                   server.xpCmdShellEnabled as xpCmdShellEnabled
        """, name="sccm_service_account_paths")

        paths = []
        for row in rows:
            paths.append({
                'attack_type': 'service_account',
                'principal_sid': row.get('serviceAccountSid'),
                'principal_name': row.get('serviceAccountName') or '',
                'principal_type': row.get('serviceAccountType') or '',
                'target_name': 'SQL Server Service Account',
                'target_type': 'MSSQL_Server',
                'database_name': ', '.join(row.get('sccmDatabases') or []),
                'server_name': row.get('sqlServer') or '',
                'xp_cmdshell_enabled': row.get('xpCmdShellEnabled', False),
                'path_edges': ['MSSQL_ServiceAccountFor'],
                'path_length': 1,
            })
        return paths

    def _format_principal(self, info):
        paths = info['paths']
        seen = set()
        deduped = []

        for path in paths:
            attack = path.get('attack_type', '')
            dedup = (attack, path.get('target_name', ''), tuple(path.get('path_edges', [])))
            if dedup in seen:
                continue
            seen.add(dedup)
            deduped.append((attack, path))

        deduped.sort(key=lambda x: (
            0 if x[0] == 'privilege_escalation' else 1 if x[0] == 'coercion' else 2,
            x[1].get('path_length', 0)
        ))

        lines = []
        for attack, path in deduped:
            line = self._format_path_line(attack, path)
            if line:
                lines.append(line)
        return lines

    def _format_path_line(self, attack_type, path):
        server = (path.get('server_name') or '').split(':')[0]
        server_display = server.lower() if server else 'unknown'
        xp = path.get('xp_cmdshell_enabled', False)
        rce_suffix = "xp_cmdshell ENABLED" if xp else "can enable xp_cmdshell"

        if attack_type == 'privilege_escalation':
            chain = self._build_chain(path)
            target_type = path.get('target_type', '')
            target_name = path.get('target_name', '')

            if target_type == 'SCCM_Site':
                impact = "RCE on all managed clients"
            else:
                impact = f"{rce_suffix} on {server_display}"

            return f"{chain} -> {impact}" if chain else impact

        elif attack_type == 'coercion':
            target_login = self._clean_name(path.get('target_name', '') or 'unknown login')
            principal_name = self._clean_name(path.get('principal_name', '') or 'principal')
            return f"{principal_name} -> CoerceAndRelayToMSSQL -> {target_login} -> {rce_suffix} on {server_display}"

        elif attack_type == 'service_account':
            principal_name = self._clean_name(path.get('principal_name', '') or 'principal')
            return f"{principal_name} -> MSSQL_ServiceAccountFor -> {server_display} -> {rce_suffix}"

        return ""

    def _build_chain(self, path):
        edges = path.get('path_edges', [])
        nodes = path.get('path_node_names', [])

        if not edges or not nodes:
            return ""

        parts = [self._clean_name(nodes[0])]
        for i, edge in enumerate(edges):
            next_name = self._clean_name(nodes[i + 1]) if i + 1 < len(nodes) else "?"
            parts.append(edge)
            parts.append(next_name)

        return " -> ".join(parts)

    def _clean_name(self, name):
        if not name:
            return "?"
        if '\\' in name:
            name = name.split('\\')[-1]
        if ':' in name:
            name = name.split(':')[0]
        return name
