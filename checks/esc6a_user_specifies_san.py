"""
AD CS ESC6a: EDITF_ATTRIBUTESUBJECTALTNAME2 enabled on CA, exploitable on
pre-May-2022 (KB5014754) DCs. Any auth-enabled template with low-privilege
enrolment can be abused — the CA-level flag lets the attacker supply the SAN
directly. Distinct from ESC6b, which additionally requires the template to
lack the SID security extension.
"""

from checks.core import check
from checks.adcs_base import ADCSCheck


@check(risk="Critical", category="ESC6a — CA Allows User-Specified SAN (pre-patch)")
class ESC6aUserSpecifiesSANCheck(ADCSCheck):

    def execute(self):
        if not self.neo4j_data:
            return {}
        target_groups = self._get_target_groups()
        if not target_groups:
            return {}
        rows = self._query_templates("""
            MATCH (g:Group)-[:Enroll|AutoEnroll]->(t:CertTemplate)-[:PublishedTo]->(ca:EnterpriseCA)
            WHERE ca.isuserspecifiessanenabled = true
              AND t.authenticationenabled = true
              AND t.requiresmanagerapproval = false
              AND coalesce(t.authorizedsignatures, 0) = 0
              AND g.name IN $target_groups
            RETURN t.name AS template, ca.caname AS ca_name, ca.dnshostname AS ca_host,
                   collect(DISTINCT g.name) AS abusers
            ORDER BY template
        """, {'target_groups': target_groups})
        return self._format_results(rows) if rows else {}
