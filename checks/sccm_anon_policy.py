"""
SCCM anonymous policy retrieval via alternate auth endpoint.

SCCM 2403+ introduced ccm_system_altauth/request which permits client
registration without a certificate. ConfigManBearPig doesn't probe this
endpoint, so all management points are flagged for manual verification.

References:
- https://github.com/subat0mik/Misconfiguration-Manager/
- https://github.com/SpecterOps/ConfigManBearPig
"""

from collections import defaultdict

from checks.core import Check, check


@check(risk="Medium", category="SCCM Potential Anonymous Policy Retrieval via Alternate Auth Endpoint", entity="computer", data=[], requires=["sccm"])
class SCCMAnonPolicyCheck(Check):

    def execute(self):
        mps = self._fetch_management_points()
        if not mps:
            return {}

        per_sid = defaultdict(list)
        for mp in mps:
            sid = mp.get('sid')
            if not sid:
                continue
            hostname = mp.get('hostname', 'unknown')
            site_code = mp.get('site_code', '')
            desc = f"https://{hostname}/ccm_system_altauth/request"
            if site_code:
                desc += f" (Site {site_code})"
            per_sid[sid].append(desc)
        return {sid: self.finding('\n'.join(descs)) for sid, descs in per_sid.items()}

    def _fetch_management_points(self):
        cdf = self._domain_condition("c")
        comp_filter = f"\n        AND true{cdf}" if cdf else ""

        rows = self.query(f"""
            MATCH (c:Computer)
            WHERE c.SCCMSiteSystemRoles IS NOT NULL
            AND coalesce(c.enabled, true) = true{comp_filter}
            UNWIND c.SCCMSiteSystemRoles as role
            WITH c, trim(split(role, '@')[1]) as site_code,
                 trim(split(role, '@')[0]) as role_name
            WHERE role_name = 'SMS Management Point'
            RETURN DISTINCT
                c.objectid as sid,
                {self.host_name_expr("c", lower=False)} as hostname,
                site_code
        """, name="management_points")

        mps = []
        seen = set()
        for row in rows:
            sid = row.get('sid')
            hostname = (row.get('hostname') or '').lower()
            site_code = row.get('site_code') or ''
            if not sid or not hostname:
                continue
            key = (sid, site_code)
            if key in seen:
                continue
            seen.add(key)
            mps.append({
                'sid': sid,
                'hostname': hostname,
                'site_code': site_code,
            })
        return mps
