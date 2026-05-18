from collections import defaultdict

from checks.core import Check, check
from checks.core.platform_mixins import MSSQLDomainMixin
from modules.opengraph_contracts import mssql_host_mapping_requirement


@check(risk="High", category="MSSQL Server Vulnerable to NTLM Relay", entity="computer", data=[], requires=["mssql"])
class MSSQLNTLMRelayCheck(MSSQLDomainMixin, Check):
    OPENGRAPH_REQUIREMENTS = (
        mssql_host_mapping_requirement("mssql_ntlm_relay"),
    )

    def execute(self):
        servers = self._get_servers()
        if not servers:
            return {}

        login_info = self._get_login_info()
        relay_targets = self._get_relay_targets()

        per_sid = defaultdict(list)
        for row in servers:
            display_account = row.get('resolvedAccount')
            if not display_account:
                continue

            server_name = row.get('serverName')
            host_sid = row.get('hostSid')
            host_name = row.get('hostName')
            if not server_name or not host_sid or not host_name:
                continue
            server_lower = server_name.lower()
            host_name = host_name.lower()

            server_logins = login_info.get(server_lower)
            if not server_logins:
                continue

            who_str = self._format_who_can_login(server_logins)

            per_server_targets = [
                display for target_name, display in relay_targets
                if target_name != host_name
            ]

            if per_server_targets:
                relay_str = f"Relay to {', '.join(per_server_targets)}"
            else:
                relay_str = "No current relay targets with SMB signing disabled"

            desc = f"{who_str} -> xp_dirtree coercion ({display_account}) -> {relay_str}"
            if desc not in per_sid[host_sid]:
                per_sid[host_sid].append(desc)

        return {sid: self.finding('\n'.join(descs)) for sid, descs in per_sid.items()}

    def _get_servers(self):
        domain_filter = self._server_domain_condition("server.name")
        where = f"\nWHERE server.serviceAccount IS NOT NULL{domain_filter}"

        return self.query(f"""
            MATCH (server:MSSQL_Server){where}
            MATCH (host:Computer)-[:MSSQL_HostFor]->(server)
            WITH server, host,
                 toLower(CASE
                   WHEN server.serviceAccount CONTAINS '\\\\' THEN split(server.serviceAccount, '\\\\')[1]
                   WHEN server.serviceAccount CONTAINS '@' THEN split(server.serviceAccount, '@')[0]
                   ELSE server.serviceAccount
                 END) as sam,
                 toUpper(CASE
                   WHEN server.serviceAccount CONTAINS '\\\\' THEN split(server.serviceAccount, '\\\\')[0]
                   WHEN server.serviceAccount CONTAINS '@' THEN split(server.serviceAccount, '@')[1]
                   ELSE host.domain
                 END) as candidate
            OPTIONAL MATCH (d:Domain)
            WHERE toUpper(d.name) = candidate OR toUpper(d.netbios) = candidate
            WITH server, host, sam, coalesce(toUpper(d.name), candidate) as svc_domain
            OPTIONAL MATCH (u:User)
            WHERE toLower(u.samaccountname) = sam AND toUpper(u.domain) = svc_domain
            AND NOT u.samaccountname ENDS WITH '$'
            RETURN server.name AS serverName,
                   server.serviceAccount AS serviceAccount,
                   host.objectid AS hostSid,
                   host.name AS hostName,
                   u.name AS resolvedAccount
        """, name="mssql_ntlm_servers")

    def _get_login_info(self):
        domain_filter = self._server_domain_condition("login.SQLServer")
        where = f"\nWHERE login.type IN ['WINDOWS_LOGIN', 'WINDOWS_GROUP', 'WINDOWS_USER']{domain_filter}"

        individual = self.query(f"""
            MATCH (login:MSSQL_Login){where}
            RETURN login.name AS name,
                   login.type AS type,
                   login.SQLServer AS server
        """, name="mssql_ntlm_logins")

        group_cond = self._default_group_condition()
        login_filter = self._server_domain_condition("login.SQLServer")
        login_where = f"\nWHERE true{login_filter}" if login_filter else ""

        groups = self.query(f"""
            MATCH (g:Group)
            WHERE {group_cond}
            MATCH (g)-[:MSSQL_HasLogin]->(login:MSSQL_Login){login_where}
            RETURN g.name AS name, login.SQLServer AS server
        """, name="mssql_ntlm_group_logins")

        info = {}
        for row in individual:
            name = row.get('name', '')
            server = row.get('server', '')
            if not name or not server:
                continue

            name_upper = name.upper()
            if name_upper.startswith('NT AUTHORITY') or name_upper.startswith('NT SERVICE'):
                continue

            server_lower = server.lower()
            if server_lower not in info:
                info[server_lower] = {'users': [], 'computers': [], 'groups': []}

            if name_upper.startswith('BUILTIN\\'):
                info[server_lower]['groups'].append(name.split('\\', 1)[1])
            elif name.endswith('$'):
                info[server_lower]['computers'].append(name)
            else:
                info[server_lower]['users'].append(name)

        for row in groups:
            name = row.get('name', '')
            server = row.get('server', '')
            if not name or not server:
                continue
            server_lower = server.lower()
            if server_lower not in info:
                info[server_lower] = {'users': [], 'computers': [], 'groups': []}
            info[server_lower]['groups'].append(name)

        return info

    def _get_relay_targets(self):
        cdf = self._domain_condition("c")
        rows = self.query(f"""
            MATCH (c:Computer)
            WHERE c.smbsigning = false AND c.name IS NOT NULL {cdf}
            RETURN c.name AS name, c.operatingsystem AS os
        """, name="mssql_ntlm_relay_targets")

        return [
            (row['name'].lower(), f"{row['name']} ({row.get('os') or 'Unknown OS'})")
            for row in rows if row.get('name')
        ]

    def _format_who_can_login(self, logins):
        who = []
        has_broad = False

        for group in logins.get('groups', []):
            if 'DOMAIN USERS' in group.upper():
                who.append(f"{group} (all domain users)")
                has_broad = True
            elif 'DOMAIN COMPUTERS' in group.upper():
                who.append(f"{group} (all domain computers)")
                has_broad = True
            elif 'AUTHENTICATED USERS' in group.upper():
                who.append(f"{group} (all authenticated users)")
                has_broad = True
            else:
                who.append(group)

        if not has_broad:
            users = logins.get('users', [])
            if users:
                shown = users[:5]
                if len(users) > 5:
                    who.append(f"{', '.join(shown)} (+{len(users)-5} more users)")
                else:
                    who.append(', '.join(shown))

            computers = logins.get('computers', [])
            if computers:
                shown = computers[:3]
                if len(computers) > 3:
                    who.append(f"{', '.join(shown)} (+{len(computers)-3} more computers)")
                else:
                    who.append(', '.join(shown))

        return ' | '.join(who) if who else "Users"
