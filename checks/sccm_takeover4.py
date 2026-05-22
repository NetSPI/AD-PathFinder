"""
TAKEOVER-4: NTLM relay from CAS to child primary site server.

Requires CAS hierarchy with child site server SMB signing disabled.

References:
- https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-4/
"""

from collections import defaultdict

from checks.core import Check, check
from checks.core.platform_mixins import SCCMDomainMixin


@check(risk="Critical", category="SCCM CAS to Child Site Relay (TAKEOVER-4)", entity="computer", data=[], requires=["sccm"])
class SCCMTakeover4Check(SCCMDomainMixin, Check):

    def execute(self):
        paths = self._fetch_paths()
        if not paths:
            return {}

        per_sid = defaultdict(list)
        for path in paths:
            target_sid = path.get('target_sid')
            if not target_sid:
                continue
            desc = self.format_relay_finding(
                path.get('site_server') or '',
                path.get('target_server', 'unknown'),
                site=path.get('site_code') or None,
            )
            if desc and desc not in per_sid[target_sid]:
                per_sid[target_sid].append(desc)
        return {sid: self.finding('\n'.join(descs)) for sid, descs in per_sid.items()}

    def _fetch_paths(self):
        sdf = self._site_domain_condition("parent_site")

        rows = self.query(f"""
            MATCH (parent_site:SCCM_Site)-[:SCCM_AdminsReplicatedTo]->(child_site:SCCM_Site)
            WHERE child_site.parentSiteCode <> "None" {sdf}

            OPTIONAL MATCH (cas_comp:Computer)
            WHERE cas_comp.SCCMSiteSystemRoles IS NOT NULL
            AND coalesce(cas_comp.enabled, true) = true
            AND any(role IN cas_comp.SCCMSiteSystemRoles
                    WHERE role = 'SMS Site Server@' + parent_site.siteCode)
            WITH parent_site, child_site,
                 collect(DISTINCT {self.host_name_expr("cas_comp")}) as cas_servers

            MATCH (child_comp:Computer)
            WHERE child_comp.SCCMSiteSystemRoles IS NOT NULL
            AND coalesce(child_comp.enabled, true) = true
            AND any(role IN child_comp.SCCMSiteSystemRoles
                    WHERE role = 'SMS Site Server@' + child_site.siteCode)
            AND child_comp.SMBSigningRequired = false

            RETURN DISTINCT
                child_site.siteCode as site_code,
                coalesce(parent_site.siteCode, parent_site.name) as parent_site_code,
                CASE WHEN size(cas_servers) > 0 THEN cas_servers[0] ELSE '' END as site_server,
                {self.host_name_expr("child_comp")} as target_server,
                child_comp.objectid as target_sid
        """, name="takeover4_paths")

        paths = []
        seen = set()
        for row in rows:
            site_code = row.get('site_code') or ''
            target_server = row.get('target_server') or ''
            target_sid = row.get('target_sid') or ''

            if not site_code or not target_server or not target_sid:
                continue

            dedup_key = (site_code, target_sid)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            paths.append({
                'site_code': site_code,
                'parent_site_code': row.get('parent_site_code') or '',
                'site_server': row.get('site_server') or '',
                'target_server': target_server,
                'target_sid': target_sid,
            })
        return paths
