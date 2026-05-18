from checks.core import Check, check
from checks.core.platform_mixins import MSSQLDomainMixin

_SYSTEM_DBS = {'master', 'msdb', 'tempdb'}


@check(risk="Medium", category="MSSQL Login", entity="user", data=[], requires=["mssql"])
class MSSQLLoginsCheck(MSSQLDomainMixin, Check):

    def execute(self):
        logins = self._fetch_logins()
        if not logins:
            return {}

        admin_users, admin_computers = self.neo4j_data.get_admin_users_and_computers()
        admin_set = set()
        if admin_users:
            admin_set.update(u.upper() for u in admin_users)
        if admin_computers:
            admin_set.update(c.upper() for c in admin_computers)

        by_entity = {}
        for row in logins:
            sid = row.get('entitySid')
            if not sid:
                continue
            name = (row.get('entityName') or '').upper()
            if not row.get('isGroup') and name in admin_set:
                continue
            by_entity.setdefault(sid, []).append(row)

        results = {}
        for sid, rows in by_entity.items():
            msg = self._format_entity(rows)
            if msg:
                results[sid] = self.finding(msg)
        return results

    def _fetch_logins(self):
        server_cond = self._server_domain_condition("login.SQLServer")
        domain_cond = self._domain_condition("entity")

        users = self.query(f"""
            MATCH (entity)-[:MSSQL_HasLogin]->(login:MSSQL_Login)
            WHERE (entity:User OR entity:Computer){domain_cond}{server_cond}
            OPTIONAL MATCH (login)-[:MSSQL_MemberOf]->(sRole:MSSQL_ServerRole)
            OPTIONAL MATCH (login)-[:MSSQL_IsMappedTo]->(dbUser:MSSQL_DatabaseUser)
            OPTIONAL MATCH (dbUser)-[:MSSQL_MemberOf]->(dbRole:MSSQL_DatabaseRole)
            OPTIONAL MATCH (dbRole)-[cap]->(capTarget)
            WHERE type(cap) IN ['MSSQL_ControlDB', 'MSSQL_GrantAnyDBPermission', 'MSSQL_Control']
            RETURN entity.objectid AS entitySid,
                   entity.name AS entityName,
                   false AS isGroup,
                   login.SQLServer AS server,
                   sRole.name AS serverRole,
                   dbUser.database AS database,
                   dbUser.explicitPermissions AS permissions,
                   dbRole.name AS dbRole,
                   type(cap) AS capability
        """, name="mssql_user_logins")

        group_cond = self._default_group_condition()
        groups = self.query(f"""
            MATCH (g:Group)
            WHERE {group_cond}
            MATCH (g)-[:MSSQL_HasLogin]->(login:MSSQL_Login)
            WHERE true{server_cond}
            OPTIONAL MATCH (login)-[:MSSQL_MemberOf]->(sRole:MSSQL_ServerRole)
            OPTIONAL MATCH (login)-[:MSSQL_IsMappedTo]->(dbUser:MSSQL_DatabaseUser)
            OPTIONAL MATCH (dbUser)-[:MSSQL_MemberOf]->(dbRole:MSSQL_DatabaseRole)
            OPTIONAL MATCH (dbRole)-[cap]->(capTarget)
            WHERE type(cap) IN ['MSSQL_ControlDB', 'MSSQL_GrantAnyDBPermission', 'MSSQL_Control']
            RETURN g.objectid AS entitySid,
                   g.name AS entityName,
                   true AS isGroup,
                   login.SQLServer AS server,
                   sRole.name AS serverRole,
                   dbUser.database AS database,
                   dbUser.explicitPermissions AS permissions,
                   dbRole.name AS dbRole,
                   type(cap) AS capability
        """, name="mssql_group_logins")

        return users + groups

    def _format_entity(self, rows):
        servers = {}
        for row in rows:
            server = row.get('server', '')
            if not server:
                continue
            if server not in servers:
                servers[server] = {'roles': set(), 'databases': {}}
            srv = servers[server]

            sr = row.get('serverRole')
            if sr and sr.upper() != 'PUBLIC':
                srv['roles'].add(sr)

            db = row.get('database')
            if not db or db.lower() in _SYSTEM_DBS:
                continue
            if db not in srv['databases']:
                srv['databases'][db] = {'roles': set(), 'capabilities': set(), 'permissions': []}
            dinfo = srv['databases'][db]

            role_name = row.get('dbRole', '')
            if role_name:
                clean = role_name.split('@')[0] if '@' in role_name else role_name
                dinfo['roles'].add(clean.lower())

            cap = row.get('capability')
            if cap:
                dinfo['capabilities'].add(cap)

            perms = row.get('permissions')
            if perms and not dinfo['permissions']:
                dinfo['permissions'] = perms

        lines = []
        for server, srv in sorted(servers.items()):
            lines.append(f"└─ SQL Login on {server}")

            if srv['databases']:
                db_items = sorted(srv['databases'].items())
                for i, (db, dinfo) in enumerate(db_items):
                    is_last = (i == len(db_items) - 1)
                    connector = "└─" if is_last else "├─"
                    lines.append(f"   {connector} Database: {db}")

                    sub_prefix = "   " if is_last else "│  "
                    sub = []
                    roles_str = ', '.join(sorted(dinfo['roles'])) if dinfo['roles'] else 'public'
                    sub.append(f"Roles: {roles_str}")

                    if dinfo['permissions']:
                        sub.append(f"Permissions: {', '.join(dinfo['permissions'])}")

                    if 'MSSQL_ControlDB' in dinfo['capabilities']:
                        sub.append("ATTACK PATH: Full database control")
                    if 'MSSQL_GrantAnyDBPermission' in dinfo['capabilities']:
                        sub.append("ATTACK PATH: Can grant any database permission")

                    for j, item in enumerate(sub):
                        is_last_sub = (j == len(sub) - 1)
                        sub_conn = "└─" if is_last_sub else "├─"
                        lines.append(f"   {sub_prefix}{sub_conn} {item}")
            elif srv['roles']:
                lines.append(f"   └─ Server Roles: {', '.join(sorted(srv['roles']))}")
            else:
                lines.append(f"   └─ No database access")

        return '\n'.join(lines) if lines else ""
