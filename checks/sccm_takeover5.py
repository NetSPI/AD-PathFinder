"""
TAKEOVER-5: NTLM relay to SMS Provider AdminService (HTTPS).

Requires SMS Provider on different host than site server.
ConfigManBearPig's CoerceAndRelayToAdminService edge confirms viability.

References:
- https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-5/
"""

from collections import defaultdict

from checks.core import Check, check
from checks.core.platform_mixins import SCCMDomainMixin


@check(risk="Critical", category="SCCM Hierarchy Takeover via AdminService Relay (TAKEOVER-5)", entity="computer", data=[], requires=["sccm"])
class SCCMTakeover5Check(SCCMDomainMixin, Check):

    def execute(self):
        paths = self._fetch_paths()
        if not paths:
            return {}

        per_sid = defaultdict(list)
        for path in paths:
            target_sid = path.get('target_sid')
            if not target_sid:
                continue
            desc = self._format_relay_line(path)
            if desc and desc not in per_sid[target_sid]:
                per_sid[target_sid].append(desc)
        return {sid: self.finding('\n'.join(descs)) for sid, descs in per_sid.items()}

    def _fetch_paths(self):
        sdf = self._site_domain_condition()
        rows = self.query(f"""
            MATCH (g)-[:CoerceAndRelayToAdminService]->(site:SCCM_Site)
            WHERE true {sdf}
            WITH site

            MATCH (ss_comp:Computer)
            WHERE ss_comp.SCCMSiteSystemRoles IS NOT NULL
            AND coalesce(ss_comp.enabled, true) = true
            AND any(role IN ss_comp.SCCMSiteSystemRoles
                    WHERE role = 'SMS Site Server@' + site.siteCode)
            WITH site,
                 collect(DISTINCT ss_comp.objectid) as site_server_sids,
                 collect(DISTINCT {self.host_name_expr("ss_comp", lower=False)}) as site_servers

            MATCH (sp_comp:Computer)
            WHERE sp_comp.SCCMSiteSystemRoles IS NOT NULL
            AND coalesce(sp_comp.enabled, true) = true
            AND any(role IN sp_comp.SCCMSiteSystemRoles
                    WHERE role = 'SMS Provider@' + site.siteCode)
            WITH site, site_server_sids, site_servers,
                 sp_comp.objectid as provider_sid,
                 {self.host_name_expr("sp_comp", lower=False)} as sms_provider_host

            WHERE NOT provider_sid IN site_server_sids

            UNWIND site_servers as site_server_host

            RETURN DISTINCT
                site.siteCode as site_code,
                site_server_host as site_server,
                sms_provider_host as sms_provider,
                provider_sid as target_sid
        """, name="takeover5_paths")

        paths = []
        seen = set()
        for row in rows:
            site_code = row.get('site_code') or ''
            sms_provider = row.get('sms_provider') or ''
            target_sid = row.get('target_sid') or ''

            if not site_code or not sms_provider or not target_sid:
                continue

            dedup_key = (site_code, target_sid)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            paths.append({
                'site_code': site_code,
                'site_server': row.get('site_server') or '',
                'sms_provider': sms_provider,
                'target_sid': target_sid,
            })
        return paths

    def _format_relay_line(self, path):
        site_server = path.get('site_server', 'unknown')
        sms_provider = path.get('sms_provider', 'unknown')
        site_code = path.get('site_code', '')

        desc = f"Coerce {site_server} -> CoerceAndRelayToAdminService > https://{sms_provider}/AdminService"

        if site_code:
            desc += f" (Site {site_code})"

        return desc
