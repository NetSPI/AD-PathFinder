from collections import defaultdict

from checks.core import Check, check


@check(risk="High", category="ESC8-vulnerable Enterprise CAs",
       entity="computer", data=["enterprise_cas"])
class ESC8VulnerableCaCheck(Check):

    def execute(self):
        enterprise_cas = self.get_enterprise_cas()
        if not enterprise_cas:
            return {}

        per_host = defaultdict(list)
        for ca in enterprise_cas:
            if not ca:
                continue

            if ca.get('hasvulnerableendpoint') is True:
                hostname = ca.get('dnshostname', 'Unknown hostname')
                caname = ca.get('caname', 'Unknown CA')
                if caname not in per_host[hostname]:
                    per_host[hostname].append(caname)

        return {
            hostname: self.finding(f"({', '.join(canames)})", inline=True)
            for hostname, canames in per_host.items()
        }