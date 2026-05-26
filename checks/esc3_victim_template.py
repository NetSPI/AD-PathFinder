"""
AD CS ESC3 victim template (a.k.a. "ESC3 target template"): the second half of
the ESC3 attack chain. Fires only when an ESC3.1 enrollment-agent template
exists on the same CA, so a fired finding always represents a complete chain.

Victim template criteria (matching Certipy's find.py):
  - authenticates (Client Authentication / Smart Card Logon EKU)
  - is schema v1 (legacy: arbitrary co-signing), OR
    is schema v2+ and requires a Cert Request Agent co-signature
  - does not require manager approval
  - allows low-privilege enrolment

The principals reported are those who can enrol for the victim template
*via* the paired ESC3 agent certificate, not direct abusers of the victim
template alone.
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
            MATCH (a_g:Group)-[:Enroll|AutoEnroll]->(agent_t:CertTemplate)-[:PublishedTo]->(ca:EnterpriseCA)
            WHERE $cert_req_agent IN agent_t.effectiveekus
              AND agent_t.requiresmanagerapproval = false
              AND coalesce(agent_t.authorizedsignatures, 0) = 0
              AND a_g.name IN $target_groups
            WITH DISTINCT ca
            MATCH (g:Group)-[:Enroll|AutoEnroll]->(t:CertTemplate)-[:PublishedTo]->(ca)
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

    def _format_results(self, rows):
        results = {}
        for row in rows:
            template = row.get('template')
            abusers = row.get('abusers')
            if not template or not abusers:
                continue
            tname = self._strip_domain(template)
            groups = self._format_groups(abusers)
            ca = row.get('ca_name', '')
            host = row.get('ca_host', '')
            results[f"{tname} ({ca} on {host})"] = self.finding(
                f"{groups} (via paired ESC3 agent cert)"
            )
        return results
