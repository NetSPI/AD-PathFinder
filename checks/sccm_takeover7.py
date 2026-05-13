"""
TAKEOVER-7: NTLM relay between HA site servers.

Requires 2+ site servers for the same site with SMB signing disabled
on at least one. Each site server is local admin on the other by default.

References:
- https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-7/
"""

from collections import defaultdict

from checks.core import Check, check


@check(risk="Critical", category="SCCM HA Site Server Relay (TAKEOVER-7)", entity="computer", data=[], requires=["sccm"])
class SCCMTakeover7Check(Check):

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
                path.get('coerce_server', ''),
                path.get('target_server', 'unknown'),
                site=path.get('site_code') or None,
            )
            if desc and desc not in per_sid[target_sid]:
                per_sid[target_sid].append(desc)
        return {sid: self.finding('\n'.join(descs)) for sid, descs in per_sid.items()}

    def _fetch_paths(self):
        cdf = self._domain_condition("role_comp")
        comp_filter = f"\n    AND true{cdf}" if cdf else ""

        rows = self.query(f"""
            MATCH (role_comp:Computer)
            WHERE role_comp.SCCMSiteSystemRoles IS NOT NULL{comp_filter}
            UNWIND role_comp.SCCMSiteSystemRoles as role
            WITH role_comp,
                 trim(split(role, '@')[0]) as role_name,
                 trim(split(role, '@')[1]) as site_code
            WHERE role_name = 'SMS Site Server'

            WITH site_code,
                 collect(DISTINCT {{host: {self.host_name_expr("role_comp")},
                                   sid: role_comp.objectid,
                                   smb_required: role_comp.SMBSigningRequired}}) as site_servers
            WHERE size(site_servers) >= 2

            UNWIND site_servers as target
            WITH site_code, site_servers, target
            WHERE target.smb_required = false

            UNWIND site_servers as coerce
            WITH site_code, target, coerce
            WHERE coerce.sid <> target.sid

            OPTIONAL MATCH ()-[:CoerceAndRelayToSMB]->(smb_t)
            WHERE smb_t.objectid = target.sid

            RETURN DISTINCT
                site_code,
                target.host as target_server,
                target.sid as target_sid,
                coerce.host as coerce_server,
                smb_t IS NOT NULL as confirmed_relay
        """, name="takeover7_paths")

        paths = []
        seen = set()
        for row in rows:
            site_code = row.get('site_code') or ''
            target_server = row.get('target_server') or ''
            target_sid = row.get('target_sid') or ''
            coerce_server = row.get('coerce_server') or ''

            if not site_code or not target_server or not target_sid:
                continue

            dedup_key = (site_code, target_sid)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            paths.append({
                'site_code': site_code,
                'target_server': target_server,
                'target_sid': target_sid,
                'coerce_server': coerce_server,
                'confirmed_relay': row.get('confirmed_relay', False),
            })
        return paths
