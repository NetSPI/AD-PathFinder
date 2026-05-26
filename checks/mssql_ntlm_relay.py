from collections import defaultdict

from checks.core import Check, check
from checks.core.high_value import high_value_principal_sets_for_check, is_high_value_principal
from checks.core.platform_mixins import MSSQLDomainMixin
from modules.opengraph_contracts import mssql_host_mapping_requirement

_COMMON_GROUP_NAMES = {
    'DOMAIN USERS',
    'DOMAIN COMPUTERS',
    'AUTHENTICATED USERS',
    'EVERYONE',
    'USERS',
}

_MAX_RELAY_PRINCIPALS = 5


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
        high_value_sets = self._high_value_start_sets()

        per_sid = defaultdict(list)
        seen_by_sid = defaultdict(set)
        for row in servers:
            display_account = row.get('resolvedAccount')
            if not display_account:
                continue

            server_name = row.get('serverName')
            host_sid = row.get('hostSid')
            host_display = row.get('hostName')
            if not server_name or not host_sid or not host_display:
                continue
            server_lower = server_name.lower()
            host_name = host_display.lower()

            server_logins = login_info.get(server_lower)
            if not server_logins:
                continue

            per_server_targets = [
                display for target_name, display in relay_targets
                if target_name != host_name
            ]

            desc = self._format_relay_path(
                self._login_principals(server_logins, high_value_sets),
                host_display,
                display_account,
                per_server_targets,
            )
            if not desc:
                continue
            if desc in seen_by_sid[host_sid]:
                continue
            seen_by_sid[host_sid].add(desc)
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

            login_type = (row.get('type') or '').upper()

            if name_upper.startswith('BUILTIN\\'):
                info[server_lower]['groups'].append(name.split('\\', 1)[1])
            elif login_type == 'WINDOWS_GROUP':
                info[server_lower]['groups'].append(name)
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

    def _high_value_start_sets(self):
        return high_value_principal_sets_for_check(
            self,
            query_name="mssql_ntlm_high_value_start_principals",
        )

    def _format_relay_path(self, principals, host_name, service_account, relay_targets):
        if not relay_targets:
            return ""
        if isinstance(principals, str):
            principals = [principals]
        if not principals:
            return ""
        relay_target = ', '.join(relay_targets)
        shown = principals[:_MAX_RELAY_PRINCIPALS]
        lines = [
            f"{principal} > MSSQL_Connect > {host_name} > xp_dirtree > "
            f"{service_account} > NTLM_Relay > {relay_target}"
            for principal in shown
        ]
        remaining = len(principals) - len(shown)
        if remaining:
            lines.append(f"(+{remaining} more principals)")
        return '\n'.join(lines)

    def _login_principals(self, logins, high_value_sets=None):
        principals = []
        has_broad = False

        for group in logins.get('groups', []):
            if self._is_filtered_start_principal(group, 'Group', high_value_sets):
                continue
            group_upper = group.upper()
            if 'DOMAIN USERS' in group_upper:
                principals.append(group)
                has_broad = True
            elif 'DOMAIN COMPUTERS' in group_upper:
                principals.append(group)
                has_broad = True
            elif 'AUTHENTICATED USERS' in group_upper:
                principals.append(group)
                has_broad = True
            else:
                principals.append(group)

        if not has_broad:
            principals.extend(
                user for user in logins.get('users', [])
                if not self._is_filtered_start_principal(user, 'User', high_value_sets)
            )
            principals.extend(
                computer for computer in logins.get('computers', [])
                if not self._is_filtered_start_principal(computer, 'Computer', high_value_sets)
            )

        return self._dedupe(principals)

    def _is_filtered_start_principal(self, name, principal_type, high_value_sets):
        if not high_value_sets:
            return False
        users, computers, groups = high_value_sets
        if is_high_value_principal(name, principal_type, users, computers, groups):
            return True
        if principal_type != 'Group':
            return is_high_value_principal(name, 'Group', users, computers, groups)
        return False

    def _dedupe(self, values):
        seen = set()
        index_by_key = {}
        deduped = []
        for value in values:
            if not value:
                continue
            key = self._principal_dedupe_key(value)
            if key in seen:
                if self._prefer_principal_display(value, deduped[index_by_key[key]]):
                    deduped[index_by_key[key]] = value
                continue
            seen.add(key)
            index_by_key[key] = len(deduped)
            deduped.append(value)
        return deduped

    def _principal_dedupe_key(self, value):
        upper = value.upper()
        account = upper.split('@', 1)[0]
        domain = None

        if '@' in upper:
            _account, domain = upper.split('@', 1)
        elif '\\' in account:
            domain, account = account.split('\\', 1)

        if account in _COMMON_GROUP_NAMES:
            return f"GROUP:{self._normalize_domain_key(domain)}:{account}"

        return f"PRINCIPAL:{self._normalize_domain_key(domain)}:{account}"

    def _normalize_domain_key(self, domain):
        if not domain:
            return self._domain_filter.upper() if self._domain_filter else ""
        if '.' in domain:
            return domain
        if self._domain_filter and self._domain_filter.upper().startswith(domain + '.'):
            return self._domain_filter.upper()
        return domain

    def _prefer_principal_display(self, candidate, current):
        candidate_upper = candidate.upper()
        current_upper = current.upper()
        return '@' in candidate_upper and '@' not in current_upper
