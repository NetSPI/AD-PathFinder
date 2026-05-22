"""
TAKEOVER-2: SMB relay from site server to remote site database host.

Requires site database on different host with SMB signing disabled.
Site server machine account is local admin on DB server by default.

References:
- https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-2/
"""

from collections import defaultdict

from checks.core import Check, check
from modules.opengraph_contracts import mssql_host_mapping_requirement


@check(risk="Critical", category="SCCM Hierarchy Takeover via SMB Relay to Site Database (TAKEOVER-2)", entity="computer", data=[], requires=["sccm"])
class SCCMTakeover2Check(Check):
    OPENGRAPH_REQUIREMENTS = (
        mssql_host_mapping_requirement("sccm_takeover2"),
    )

    def execute(self):
        cdf = self._domain_condition("target")

        rows = self.query(f"""
            MATCH (g)-[:CoerceAndRelayToSMB]->(target:Computer)
                  -[:MSSQL_HostFor]->(:MSSQL_Server)-[:MSSQL_Contains]->(db:MSSQL_Database)
                  -[:SCCM_AssignAllPermissions]->(site:SCCM_Site)
            WHERE target.SMBSigningRequired = false
            AND coalesce(target.enabled, true) = true {cdf}

            OPTIONAL MATCH (ss:Computer)
            WHERE ss.SCCMSiteSystemRoles IS NOT NULL
            AND coalesce(ss.enabled, true) = true
            AND any(role IN ss.SCCMSiteSystemRoles WHERE role = 'SMS Site Server@' + site.siteCode)
            AND ss.objectid <> target.objectid

            RETURN DISTINCT
                site.siteCode as site_code,
                {self.host_name_expr("ss")} as site_server,
                {self.host_name_expr("target")} as target_server,
                target.objectid as target_sid
        """, name="takeover2_paths")

        per_sid = defaultdict(list)
        for row in rows:
            target_sid = row.get('target_sid') or ''
            target_server = row.get('target_server') or ''
            if not target_sid or not target_server:
                continue

            site_server = row.get('site_server') or ''
            site_code = row.get('site_code') or ''

            desc = self.format_relay_finding(site_server, target_server, site=site_code or None)

            if desc and desc not in per_sid[target_sid]:
                per_sid[target_sid].append(desc)
        return {sid: self.finding('\n'.join(descs)) for sid, descs in per_sid.items()}
