"""
TAKEOVER-8: HTTP-to-LDAP/LDAPS NTLM relay on a domain controller.

Fires only when both halves of the SCCM TAKEOVER-8 chain are present:

  1. Relay target — a DC whose LDAP config accepts a relayed NTLM bind
     (LDAP signing not required, or LDAPS channel binding not enforced).
  2. Coerce source — an SCCM role-holder with the WebClient service
     running, so HTTP coercion (PetitPotam over WebDAV, etc.) can land.
     Per TAKEOVER-8.1–8.4, the canonical sources are: primary site
     server, SMS Provider, passive site server, site database server.
     Identified by `SCCMSiteSystemRoles` containing 'SMS Site Server@',
     'SMS Provider@', or 'SMS SQL Server@'.

Once relayed and bound to the directory as the coerced SCCM machine
account, the attacker performs RBCD or Shadow Credentials writes
against the source server's directory object to take it over, then
pivots to the SCCM Full Administrator role from that compromised host.

References:
- https://docs.specterops.io/misconfiguration-manager-docs/attack-techniques/TAKEOVER/TAKEOVER-8/takeover-8_description
- https://github.com/SpecterOps/ConfigManBearPig/blob/main/cypher_queries/SCCM%20Hierarchy%20TAKEOVER-8.json
- https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-8/
"""

from checks.core import Check, check


@check(risk="Critical",
       category="SCCM Hierarchy Takeover via HTTP-to-LDAP/LDAPS Relay on Domain Controller (TAKEOVER-8)",
       entity="computer",
       data=[],
       requires=["sccm"])
class SCCMTakeover8Check(Check):

    def execute(self):
        cdf = self._domain_condition("dc")
        sdf = self._domain_condition("src")

        rows = self.query(f"""
            MATCH (dc:Computer)-[:DCFor]->(:Domain)
            WHERE
                ((dc.ldapavailable = true AND dc.ldapsigning = false)
                 OR (dc.ldapsavailable = true AND dc.ldapsepa = false))
                AND coalesce(dc.enabled, true) = true
                {cdf}
            WITH dc,
                 (dc.ldapavailable = true AND dc.ldapsigning = false) AS ldap_relay,
                 (dc.ldapsavailable = true AND dc.ldapsepa = false) AS ldaps_relay

            MATCH (src:Computer)
            WHERE coalesce(src.webclientrunning, src.WebClientRunning, false) = true
              AND src.domain = dc.domain
              AND src.SCCMSiteSystemRoles IS NOT NULL
              AND coalesce(src.enabled, true) = true
              AND (
                any(role IN src.SCCMSiteSystemRoles WHERE role STARTS WITH 'SMS Site Server@')
                OR any(role IN src.SCCMSiteSystemRoles WHERE role STARTS WITH 'SMS Provider@')
                OR any(role IN src.SCCMSiteSystemRoles WHERE role STARTS WITH 'SMS SQL Server@')
              )
              {sdf}

            RETURN
                dc.objectid AS dc_sid,
                {self.host_name_expr("dc")} AS dc_name,
                ldap_relay,
                ldaps_relay,
                {self.host_name_expr("src")} AS src_name,
                CASE
                    WHEN any(r IN src.SCCMSiteSystemRoles WHERE r STARTS WITH 'SMS Site Server@') THEN 'Site Server'
                    WHEN any(r IN src.SCCMSiteSystemRoles WHERE r STARTS WITH 'SMS Provider@') THEN 'SMS Provider'
                    ELSE 'Site DB Server'
                END AS src_role
        """, name="takeover8_paths")

        by_dc = {}
        for row in rows:
            dc_sid = row.get('dc_sid')
            src_name = row.get('src_name')
            if not dc_sid or not src_name:
                continue
            entry = by_dc.setdefault(dc_sid, {
                'dc_name': row.get('dc_name') or 'unknown',
                'ldap_relay': row.get('ldap_relay'),
                'ldaps_relay': row.get('ldaps_relay'),
                'sources': [],
            })
            src = (src_name, row.get('src_role') or 'SCCM role')
            if src not in entry['sources']:
                entry['sources'].append(src)

        results = {}
        for dc_sid, info in by_dc.items():
            protos = []
            if info['ldap_relay']:
                protos.append('LDAP')
            if info['ldaps_relay']:
                protos.append('LDAPS')
            proto = '/'.join(protos) or 'LDAP/LDAPS'
            sources_str = ', '.join(f"{n} ({r})" for n, r in info['sources'])
            desc = f"Coerce {sources_str} -> HTTP-to-{proto} NTLM relay to {info['dc_name']}"
            results[dc_sid] = self.finding(desc)
        return results
