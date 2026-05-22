"""
TAKEOVER-1: NTLM relay to SCCM site database (EPA not enforced).

Uses CoerceAndRelayToMSSQL collector edges to walk the relay chain
to the SCCM site database.

References:
- https://posts.specterops.io/sccm-hierarchy-takeover-41929c61e087
- https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-1/
"""

from collections import defaultdict

from checks.core import Check, check
from checks.core.platform_mixins import SCCMDomainMixin
from modules.opengraph_contracts import mssql_host_mapping_requirement


@check(risk="Critical", category="SCCM Hierarchy Takeover via NTLM Relay (TAKEOVER-1)", entity="computer", data=[], requires=["sccm"])
class SCCMTakeover1Check(SCCMDomainMixin, Check):
    OPENGRAPH_REQUIREMENTS = (
        mssql_host_mapping_requirement("sccm_takeover1"),
    )

    def execute(self):
        sdf = self._site_domain_condition()
        rows = self.query(f"""
            MATCH (g)-[relay:CoerceAndRelayToMSSQL]->(login)
                  -[:MSSQL_MemberOf|MSSQL_IsMappedTo|MSSQL_ControlServer
                    |MSSQL_ControlDB|MSSQL_Contains
                    |SCCM_AssignAllPermissions*1..6]->(site:SCCM_Site)
            WHERE true {sdf}

            OPTIONAL MATCH (login)-[:MSSQL_MemberOf]->(:MSSQL_ServerRole)
                           -[:MSSQL_ControlServer]->(server:MSSQL_Server)
            OPTIONAL MATCH (target:Computer)-[:MSSQL_HostFor]->(server)
            WHERE coalesce(target.enabled, true) = true

            RETURN DISTINCT
                site.siteCode as site_code,
                relay.coercionVictimAndRelayTargetPairs as pairs,
                coalesce(server.extendedProtection, 'Unknown') as epa_status,
                target.objectid as target_sid
        """, name="takeover1_edge_paths")

        per_sid = defaultdict(list)
        seen = set()
        for row in rows:
            site_code = row.get('site_code') or ''
            target_sid = row.get('target_sid') or ''
            if not site_code or not target_sid:
                continue

            for pair in (row.get('pairs') or []):
                parts = pair.lower().replace('coerce ', '').split(', relay to ')
                if len(parts) != 2:
                    continue
                coerce_server = parts[0].strip()
                target_server = parts[1].split(':')[0].strip()

                dedup_key = (site_code, coerce_server, target_sid)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                epa = row.get('epa_status', '')
                desc = f"Coerce {coerce_server} -> MSSQL relay to {target_server}"
                if site_code:
                    desc += f" (Site {site_code})"
                if epa:
                    desc += f" [EPA: {epa}]"
                per_sid[target_sid].append(desc)

        return {sid: self.finding('\n'.join(descs)) for sid, descs in per_sid.items()}
