"""
ELEVATE-1: SMB relay from site server to other site systems.

Targets SCCM site systems (SQL, SMS Provider, etc.) on different hosts
with SMB signing disabled. Site server is local admin by default.

References:
- https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/ELEVATE/ELEVATE-1/
"""

from collections import defaultdict

from checks.core import Check, check


@check(risk="High", category="SCCM Infrastructure SMB Relay (ELEVATE-1)", entity="computer", data=[], requires=["sccm"])
class SCCMElevate1Check(Check):

    def execute(self):
        cdf = self._domain_condition("target")

        rows = self.query(f"""
            MATCH (g)-[:CoerceAndRelayToSMB]->(target:Computer)
            WHERE target.SMBSigningRequired = false
            AND coalesce(target.enabled, true) = true
            AND target.SCCMSiteSystemRoles IS NOT NULL {cdf}

            UNWIND target.SCCMSiteSystemRoles as role
            WITH target, trim(split(role, '@')[1]) as site_code, trim(split(role, '@')[0]) as role_name
            WHERE role_name <> 'SMS Site Server'

            OPTIONAL MATCH (ss:Computer)
            WHERE ss.SCCMSiteSystemRoles IS NOT NULL
            AND coalesce(ss.enabled, true) = true
            AND any(r IN ss.SCCMSiteSystemRoles WHERE r = 'SMS Site Server@' + site_code)
            AND ss.objectid <> target.objectid

            RETURN DISTINCT
                site_code,
                {self.host_name_expr("ss")} as site_server,
                {self.host_name_expr("target")} as target_server,
                target.objectid as target_sid,
                collect(DISTINCT role_name) as target_roles
        """, name="elevate1_paths")

        per_sid = defaultdict(list)
        for row in rows:
            target_sid = row.get('target_sid') or ''
            target_server = row.get('target_server') or ''
            if not target_sid or not target_server:
                continue

            site_server = row.get('site_server') or ''
            site_code = row.get('site_code') or ''
            roles = [r for r in (row.get('target_roles') or []) if r]

            desc = self.format_relay_finding(
                site_server,
                target_server,
                site=site_code or None,
                qualifier=f"({', '.join(roles)})" if roles else None,
            )

            if desc and desc not in per_sid[target_sid]:
                per_sid[target_sid].append(desc)
        return {sid: self.finding('\n'.join(descs)) for sid, descs in per_sid.items()}
