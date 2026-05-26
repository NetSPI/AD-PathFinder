"""
AD CS ESC3 victim template (a.k.a. "ESC3 target template"): the second half of
the ESC3 attack chain. Once an attacker holds an enrollment-agent certificate
(ESC3.1), they can request a certificate from a victim template on behalf of
any user, provided the template:
  - authenticates (Client Authentication / Smart Card Logon EKU)
  - is schema v1 (legacy: arbitrary co-signing), OR
    is schema v2+ and requires a Cert Request Agent co-signature
  - does not require manager approval
  - allows low-privilege enrolment

Criteria match Certipy's `find.py` ESC3 Target Template detection.
"""

from checks.core import check
from checks.adcs_base import ADCSCheck

CERT_REQ_AGENT_OID = '1.3.6.1.4.1.311.20.2.1'


@check(risk="High", category="ESC3 — Victim Template")
class ESC3VictimTemplateCheck(ADCSCheck):

    def execute(self):
        if not self.neo4j_data:
            return {}
        target_groups = self._get_target_groups()
        if not target_groups:
            return {}
        rows = self._query_templates("""
            MATCH (g:Group)-[:Enroll|AutoEnroll]->(t:CertTemplate)-[:PublishedTo]->(ca:EnterpriseCA)
            WHERE t.authenticationenabled = true
              AND t.requiresmanagerapproval = false
              AND (
                t.schemaversion = 1
                OR (
                  t.schemaversion > 1
                  AND coalesce(t.authorizedsignatures, 0) >= 1
                  AND $cert_req_agent IN coalesce(t.applicationpolicies, [])
                )
              )
              AND g.name IN $target_groups
            RETURN t.name AS template, ca.caname AS ca_name, ca.dnshostname AS ca_host,
                   collect(DISTINCT g.name) AS abusers
            ORDER BY template
        """, {'target_groups': target_groups, 'cert_req_agent': CERT_REQ_AGENT_OID})
        return self._format_results(rows) if rows else {}
