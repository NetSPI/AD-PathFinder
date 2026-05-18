"""
AD CS ESC2: Certificate templates with Any Purpose EKU or no EKU, allowing
certificates to be used for client authentication or enrollment agent abuse.
"""

from checks.core import check
from checks.adcs_base import ADCSCheck

ANY_PURPOSE_OID = '2.5.29.37.0'


@check(risk="High", category="ESC2 — Any Purpose EKU")
class ESC2AnyPurposeCheck(ADCSCheck):

    def execute(self):
        if not self.neo4j_data:
            return {}
        target_groups = self._get_target_groups()
        if not target_groups:
            return {}
        rows = self._query_templates("""
            MATCH (g:Group)-[:Enroll|AutoEnroll]->(t:CertTemplate)-[:PublishedTo]->(ca:EnterpriseCA)
            WHERE ($any_purpose IN t.effectiveekus OR size(t.effectiveekus) = 0)
              AND t.requiresmanagerapproval = false
              AND coalesce(t.authorizedsignatures, 0) = 0
              AND g.name IN $target_groups
            RETURN t.name AS template, ca.caname AS ca_name, ca.dnshostname AS ca_host,
                   collect(DISTINCT g.name) AS abusers
            ORDER BY template
        """, {'target_groups': target_groups, 'any_purpose': ANY_PURPOSE_OID})
        return self._format_results(rows) if rows else {}
