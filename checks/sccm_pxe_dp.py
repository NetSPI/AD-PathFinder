"""
SCCM Distribution Point - PXE Boot Review.

Reports Distribution Point systems where CMBP's preserved REMINST signal
confirms PXE support.

References:
- https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-4/
"""

from collections import defaultdict

from checks.core import Check, check


@check(risk="Medium", category="SCCM Distribution Point - PXE Boot Review", entity="computer", data=[], requires=["sccm"])
class SCCMPxeDPCheck(Check):

    def execute(self):
        dps = self._fetch_distribution_points()
        if not dps:
            return {}

        per_sid = defaultdict(list)
        for dp in dps:
            sid = dp.get('sid')
            if not sid:
                continue
            hostname = dp.get('hostname', 'unknown')
            site_code = dp.get('site_code', '')
            desc = hostname
            if site_code:
                desc += f" (Site {site_code})"
            desc += " - PXE confirmed via REMINST"
            per_sid[sid].append(desc)
        return {sid: self.finding('\n'.join(descs)) for sid, descs in per_sid.items()}

    def _fetch_distribution_points(self):
        cdf = self._domain_condition("c")
        comp_filter = f"\n        AND true{cdf}" if cdf else ""

        rows = self.query(f"""
            MATCH (c:Computer)
            WHERE c.SCCMSiteSystemRoles IS NOT NULL
            AND coalesce(c.enabled, true) = true{comp_filter}
            UNWIND c.SCCMSiteSystemRoles as role
            WITH c, trim(split(role, '@')[1]) as site_code,
                 trim(split(role, '@')[0]) as role_name
            WHERE role_name CONTAINS 'Distribution Point'
            WITH c, site_code,
                 coalesce(c.SCCMIsPXESupportEnabled, false) as pxe_confirmed
            WHERE pxe_confirmed = true
            RETURN DISTINCT
                c.objectid as sid,
                {self.host_name_expr("c", lower=False)} as hostname,
                site_code
        """, name="pxe_distribution_points")

        dps = []
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
            dps.append({
                'sid': sid,
                'hostname': hostname,
                'site_code': site_code,
            })
        return dps
