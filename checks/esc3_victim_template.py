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

# Member space of the four low-priv groups, for chain-exploitability checks.
# AUTH USERS / EVERYONE cover both users and computers; DOMAIN USERS covers
# user accounts only; DOMAIN COMPUTERS covers computer accounts only.
_GROUP_MEMBER_SPACE = {
    'AUTHENTICATED USERS': frozenset({'USERS', 'COMPUTERS'}),
    'EVERYONE': frozenset({'USERS', 'COMPUTERS'}),
    'DOMAIN USERS': frozenset({'USERS'}),
    'DOMAIN COMPUTERS': frozenset({'COMPUTERS'}),
}


def _member_space(group_names):
    space = set()
    for name in group_names:
        bare = name.split('@', 1)[0].upper()
        space |= _GROUP_MEMBER_SPACE.get(bare, frozenset())
    return space


def _contributing(groups, other_space):
    return [g for g in groups if _member_space([g]) & other_space]


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
            WITH ca,
                 collect(DISTINCT agent_t.name) AS agent_templates,
                 collect(DISTINCT a_g.name) AS agent_abusers
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
                   collect(DISTINCT g.name) AS abusers,
                   agent_templates, agent_abusers
            ORDER BY template
        """, {'target_groups': target_groups, 'cert_req_agent': CERT_REQ_AGENT_OID})
        return self._format_results(rows) if rows else {}

    def _format_results(self, rows):
        results = {}
        for row in rows:
            template = row.get('template')
            abusers = row.get('abusers') or []
            agent_templates = row.get('agent_templates') or []
            agent_abusers = row.get('agent_abusers') or []
            if not template or not abusers or not agent_templates or not agent_abusers:
                continue
            agent_space = _member_space(agent_abusers)
            victim_space = _member_space(abusers)
            if not (agent_space & victim_space):
                continue
            contributing_agents = _contributing(agent_abusers, victim_space)
            contributing_victims = _contributing(abusers, agent_space)
            tname = self._strip_domain(template)
            groups = self._format_groups(contributing_victims)
            agent_names = sorted(self._strip_domain(a) for a in agent_templates)
            agent_label = f"agent '{agent_names[0]}'" if len(agent_names) == 1 \
                else "agents " + ', '.join(f"'{a}'" for a in agent_names)
            agent_groups = self._format_groups(contributing_agents)
            ca = row.get('ca_name', '')
            host = row.get('ca_host', '')
            results[f"{tname} ({ca} on {host})"] = self.finding(
                f"{groups} (via paired ESC3 {agent_label} enrollable by {agent_groups})"
            )
        return results
