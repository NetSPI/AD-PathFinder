"""
AD CS ESC1: Certificate templates that allow low-privileged users to supply an
arbitrary Subject Alternative Name with Client Authentication EKU.
"""

from checks.core import check
from checks.adcs_base import ADCSCheck


@check(risk="Critical", category="ESC1 — Enrollee Supplies Subject")
class ESC1VulnerableTemplateCheck(ADCSCheck):

    def execute(self):
        if not self.neo4j_data:
            return {}
        target_groups = self._get_target_groups()
        if not target_groups:
            return {}
        rows = self._query_templates("""
            MATCH (g:Group)-[:Enroll|AutoEnroll]->(t:CertTemplate)-[:PublishedTo]->(ca:EnterpriseCA)
            WHERE t.enrolleesuppliessubject = true
              AND t.authenticationenabled = true
              AND t.requiresmanagerapproval = false
              AND coalesce(t.authorizedsignatures, 0) = 0
              AND g.name IN $target_groups
            RETURN t.name AS template, ca.caname AS ca_name, ca.dnshostname AS ca_host,
                   collect(DISTINCT g.name) AS abusers
            ORDER BY template
        """, {'target_groups': target_groups})
        return self._format_results(rows) if rows else {}
