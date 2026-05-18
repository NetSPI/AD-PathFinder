"""
AD CS ESC4: Low-privileged groups have write permissions on certificate template
AD objects, allowing modification to introduce ESC1/2/3 vulnerabilities.
"""

from checks.core import check
from checks.adcs_base import ADCSCheck


@check(risk="Critical", category="ESC4 — Template ACL Abuse")
class ESC4TemplateACLCheck(ADCSCheck):

    def execute(self):
        if not self.neo4j_data:
            return {}
        target_groups = self._get_target_groups()
        if not target_groups:
            return {}
        rows = self._query_templates("""
            MATCH (g:Group)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns]->(t:CertTemplate)-[:PublishedTo]->(ca:EnterpriseCA)
            WHERE g.name IN $target_groups
            RETURN t.name AS template, ca.caname AS ca_name, ca.dnshostname AS ca_host,
                   collect(DISTINCT g.name) AS abusers
            ORDER BY template
        """, {'target_groups': target_groups})
        return self._format_results(rows) if rows else {}
