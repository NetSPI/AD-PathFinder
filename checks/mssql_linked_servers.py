from checks.core import Check, check
from checks.core.platform_mixins import MSSQLDomainMixin
from modules.opengraph_contracts import mssql_host_mapping_requirement


@check(risk="Medium", category="MSSQL Linked Servers", entity="computer", data=[], requires=["mssql"])
class MSSQLLinkedServersCheck(MSSQLDomainMixin, Check):
    OPENGRAPH_REQUIREMENTS = (
        mssql_host_mapping_requirement("mssql_linked_servers"),
    )

    def execute(self):
        domain_filter = self._server_domain_condition("source.name")
        where = f"\nWHERE true{domain_filter}" if domain_filter else ""

        rows = self.query(f"""
            MATCH (source:MSSQL_Server)-[r:MSSQL_LinkedTo|MSSQL_LinkedAsAdmin]->(target)
            MATCH (host:Computer)-[:MSSQL_HostFor]->(source){where}
            RETURN host.objectid AS hostSid,
                   target.name AS targetServer,
                   r.localLogin AS localLogin,
                   r.remoteCurrentLogin AS remoteLogin,
                   r.remoteIsSysadmin AS remoteSysadmin,
                   r.remoteHasControlServer AS remoteControl,
                   r.remoteIsSecurityAdmin AS remoteSecAdmin,
                   r.rpcOut AS rpcOut,
                   r.path AS path
        """, name="mssql_linked_servers")

        computer_links = {}
        seen = set()

        for row in rows:
            host_sid = row.get('hostSid')
            if not host_sid:
                continue

            key = (host_sid, row.get('targetServer'), row.get('localLogin'), row.get('remoteLogin'))
            if key in seen:
                continue
            seen.add(key)

            computer_links.setdefault(host_sid, []).append(self._format_link(row))

        results = {}
        for sid, links in computer_links.items():
            results[sid] = self.finding("\n".join(sorted(links)))
        return results

    def _format_link(self, row):
        path = row.get('path', '')
        target = row.get('targetServer') or 'unknown'
        link_name = path.split(' -> ')[1] if path and ' -> ' in path else target

        local_login = row.get('localLogin') or 'unknown'
        access = "Any SQL user" if local_login == 'All Logins' else local_login

        privs = []
        if row.get('remoteSysadmin'):
            privs.append("sysadmin")
        if row.get('remoteControl'):
            privs.append("CONTROL SERVER")
        if row.get('remoteSecAdmin'):
            privs.append("securityadmin")
        if row.get('rpcOut'):
            privs.append("RPC enabled")

        remote_login = row.get('remoteLogin') or 'unknown'
        desc = f"{access} -> Linked Server [{link_name}] -> Execute as {remote_login}"
        if privs:
            desc += f" ({', '.join(privs)})"
        return desc
