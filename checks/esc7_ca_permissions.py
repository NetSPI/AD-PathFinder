"""
AD CS ESC7: Low-privileged groups have ManageCA or ManageCertificates permissions
on a CA, allowing them to manipulate CA configuration, enable templates, or
approve/deny certificate requests for arbitrary certificate issuance.
"""

from checks.core import check
from checks.adcs_base import ADCSCheck


@check(risk="Critical", category="ESC7 — CA ManageCA Permissions")
class ESC7CAPermissionsCheck(ADCSCheck):

    def execute(self):
        if not self.neo4j_data:
            return {}
        target_groups = self._get_target_groups()
        if not target_groups:
            return {}
        rows = self._query_templates("""
            MATCH (g:Group)-[:ManageCA|ManageCertificates]->(ca:EnterpriseCA)
            WHERE g.name IN $target_groups
            RETURN ca.caname AS ca_name, ca.dnshostname AS ca_host,
                   collect(DISTINCT g.name) AS abusers
        """, {'target_groups': target_groups})
        if not rows:
            return {}
        results = {}
        for row in rows:
            abusers = row.get('abusers')
            if not abusers:
                continue
            ca = row.get('ca_name', '')
            host = row.get('ca_host', '')
            results[f"{ca} ({host})"] = self.finding(self._format_groups(abusers))
        return results
