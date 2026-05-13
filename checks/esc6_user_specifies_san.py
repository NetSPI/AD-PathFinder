"""
AD CS ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 enabled on CA, combined with templates
that have CT_FLAG_NO_SECURITY_EXTENSION (ESC9). On patched systems (post-May 2022),
only templates missing the SID security extension are exploitable via SAN injection.
"""

from checks.core import check
from checks.adcs_base import ADCSCheck


@check(risk="Critical", category="ESC6 — CA Allows User-Specified SAN")
class ESC6UserSpecifiesSANCheck(ADCSCheck):

    def execute(self):
        if not self.neo4j_data:
            return {}
        target_groups = self._get_target_groups()
        if not target_groups:
            return {}
        rows = self._query_templates("""
            MATCH (g:Group)-[:Enroll|AutoEnroll]->(t:CertTemplate)-[:PublishedTo]->(ca:EnterpriseCA)
            WHERE ca.isuserspecifiessanenabled = true
              AND t.nosecurityextension = true
              AND t.authenticationenabled = true
              AND t.requiresmanagerapproval = false
              AND coalesce(t.authorizedsignatures, 0) = 0
              AND g.name IN $target_groups
            RETURN t.name AS template, ca.caname AS ca_name, ca.dnshostname AS ca_host,
                   collect(DISTINCT g.name) AS abusers
            ORDER BY template
        """, {'target_groups': target_groups})
        return self._format_results(rows) if rows else {}
