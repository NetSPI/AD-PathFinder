
from checks.core import Check

LOW_PRIV_GROUPS = {'DOMAIN USERS', 'AUTHENTICATED USERS', 'DOMAIN COMPUTERS', 'EVERYONE'}


class ADCSCheck(Check):
    REQUIRED_DATA = []
    ENTITY_TYPE = "user"

    def _get_target_groups(self):
        domain = self.neo4j_data.get_domain_name()
        if not domain:
            return None
        return [f'{g}@{domain}' for g in LOW_PRIV_GROUPS]

    def _query_templates(self, cypher, parameters):
        return self.query(cypher, parameters=parameters, name="adcs_query_templates")

    @staticmethod
    def _strip_domain(name):
        return name.split('@')[0] if '@' in name else name

    def _format_groups(self, abusers):
        return ', '.join(sorted(self._strip_domain(g) for g in abusers))

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
            results[f"{tname} ({ca} on {host})"] = self.finding(groups)
        return results
