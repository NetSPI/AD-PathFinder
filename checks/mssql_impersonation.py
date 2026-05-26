from checks.core import Check, check
from checks.core.platform_mixins import MSSQLDomainMixin
from modules.opengraph_contracts import mssql_host_mapping_requirement


@check(risk="Medium", category="MSSQL Login Impersonation", entity="computer", data=[], requires=["mssql"])
class MSSQLImpersonationCheck(MSSQLDomainMixin, Check):
    OPENGRAPH_REQUIREMENTS = (
        mssql_host_mapping_requirement("mssql_impersonation"),
    )

    def execute(self):
        domain_filter = self._server_domain_condition("sourceLogin.SQLServer")
        where = f"\nWHERE true{domain_filter}" if domain_filter else ""

        rows = self.query(f"""
            MATCH (sourceLogin:MSSQL_Login)-[:MSSQL_ExecuteAs]->(targetLogin:MSSQL_Login)
            MATCH (server:MSSQL_Server)-[:MSSQL_Contains]->(sourceLogin)
            MATCH (host:Computer)-[:MSSQL_HostFor]->(server){where}
            RETURN sourceLogin.name AS sourceLogin,
                   host.objectid AS hostSid,
                   targetLogin.name AS targetLogin
        """, name="mssql_impersonation")

        impersonation_map = {}
        host_sid_map = {}

        for row in rows:
            source = row.get('sourceLogin')
            target = row.get('targetLogin')
            host_sid = row.get('hostSid')
            if not source or not target:
                continue
            if host_sid:
                host_sid_map[source] = host_sid
            impersonation_map.setdefault(source, []).append(target)

        chains_by_host = {}
        for source, targets in impersonation_map.items():
            host_sid = host_sid_map.get(source)
            if not host_sid:
                continue
            for target in targets:
                for suffix in self._follow_chains(impersonation_map, target, frozenset({source})):
                    chain = f"{source} -> EXECUTE AS {target}"
                    if suffix:
                        chain += f" -> {suffix}"
                    chains_by_host.setdefault(host_sid, []).append(chain)

        results = {}
        for host_sid, chains in chains_by_host.items():
            results[host_sid] = self.finding("\n".join(sorted(chains)))
        return results

    def _follow_chains(self, impersonation_map, login, visited):
        if login in visited:
            return [""]
        visited = visited | {login}
        targets = impersonation_map.get(login, [])
        if not targets:
            return [""]
        suffixes = []
        for target in targets:
            if target in visited:
                continue
            for sub in self._follow_chains(impersonation_map, target, visited):
                suffixes.append(f"EXECUTE AS {target} -> {sub}" if sub else f"EXECUTE AS {target}")
        return suffixes or [""]
