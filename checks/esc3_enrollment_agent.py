"""
AD CS ESC3: Certificate templates with Certificate Request Agent EKU, allowing
holders to request certificates on behalf of other users.
"""

from checks.core import check
from checks.adcs_base import ADCSCheck

CERT_REQ_AGENT_OID = '1.3.6.1.4.1.311.20.2.1'


@check(risk="High", category="ESC3 — Enrollment Agent")
class ESC3EnrollmentAgentCheck(ADCSCheck):

    def execute(self):
        if not self.neo4j_data:
            return {}
        target_groups = self._get_target_groups()
        if not target_groups:
            return {}
        rows = self._query_templates("""
            MATCH (g:Group)-[:Enroll|AutoEnroll]->(t:CertTemplate)-[:PublishedTo]->(ca:EnterpriseCA)
            WHERE $cert_req_agent IN t.effectiveekus
              AND t.requiresmanagerapproval = false
              AND coalesce(t.authorizedsignatures, 0) = 0
              AND g.name IN $target_groups
            RETURN t.name AS template, ca.caname AS ca_name, ca.dnshostname AS ca_host,
                   collect(DISTINCT g.name) AS abusers
            ORDER BY template
        """, {'target_groups': target_groups, 'cert_req_agent': CERT_REQ_AGENT_OID})
        return self._format_results(rows) if rows else {}
