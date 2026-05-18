"""
TAKEOVER-6: SMB relay from site server to remote SMS Provider.

Requires SMS Provider on different host with SMB signing disabled.
Site server machine account is local admin on SMS Provider by default.

References:
- https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-6/
"""

from collections import defaultdict

from checks.core import Check, check


@check(risk="Critical", category="SCCM Hierarchy Takeover via SMB Relay to SMS Provider (TAKEOVER-6)", entity="computer", data=[], requires=["sccm"])
class SCCMTakeover6Check(Check):

    def execute(self):
        cdf = self._domain_condition("target")

        rows = self.query(f"""
            MATCH (g)-[:CoerceAndRelayToSMB]->(target:Computer)-[:SCCM_AssignAllPermissions]->(site:SCCM_Site)
            WHERE target.SMBSigningRequired = false {cdf}
            AND any(role IN target.SCCMSiteSystemRoles WHERE role = 'SMS Provider@' + site.siteCode)

            OPTIONAL MATCH (ss:Computer)
            WHERE ss.SCCMSiteSystemRoles IS NOT NULL
            AND any(role IN ss.SCCMSiteSystemRoles WHERE role = 'SMS Site Server@' + site.siteCode)
            AND ss.objectid <> target.objectid

            RETURN DISTINCT
                site.siteCode as site_code,
                {self.host_name_expr("ss")} as site_server,
                {self.host_name_expr("target")} as sms_provider,
                target.objectid as target_sid
        """, name="takeover6_paths")

        per_sid = defaultdict(list)
        for row in rows:
            target_sid = row.get('target_sid') or ''
            sms_provider = row.get('sms_provider') or ''
            if not target_sid or not sms_provider:
                continue

            site_server = row.get('site_server') or ''
            site_code = row.get('site_code') or ''

            desc = self.format_relay_finding(site_server, sms_provider, site=site_code or None)

            if desc and desc not in per_sid[target_sid]:
                per_sid[target_sid].append(desc)
        return {sid: self.finding('\n'.join(descs)) for sid, descs in per_sid.items()}
