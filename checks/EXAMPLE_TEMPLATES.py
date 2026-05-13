"""
Example check templates — not auto-imported, not executed.
Copy one of these as a starting point for a new check.
"""

# --- Simple property check (computer) ---
#
# from checks.core import Check, check
#
# @check(risk="High", category="Computer with Unconstrained Delegation",
#        entity="computer", data=["computers"])
# class ComputerUnconstrainedDelegationCheck(Check):
#
#     def execute(self):
#         def check_delegation(computer):
#             if computer.get('unconstrainedDelegation') is True:
#                 return self.finding("")
#             return None
#
#         return self.process_entity_results(self.get_computers(), check_delegation)


# --- Simple property check (user) ---
#
# from checks.core import Check, check
#
# @check(risk="High", category="User with Unconstrained Delegation",
#        entity="user", data=["users"])
# class UserUnconstrainedDelegationCheck(Check):
#
#     def execute(self):
#         def check_delegation(user):
#             if user.get('unconstrainedDelegation') is True:
#                 return self.finding("")
#             return None
#
#         return self.process_entity_results(self.get_users(), check_delegation)


# --- Check with details ---
#
# from checks.core import Check, check
#
# @check(risk="Medium", category="Computer with Constrained Delegation",
#        entity="computer", data=["computers"])
# class ComputerConstrainedDelegationCheck(Check):
#
#     def execute(self):
#         def check_delegation(computer):
#             delegation_info = computer.get('constrainedDelegation')
#             if isinstance(delegation_info, list) and delegation_info:
#                 delegation_str = ", ".join(delegation_info)
#                 return self.finding(f"Constrained Delegation: {delegation_str}")
#             return None
#
#         return self.process_entity_results(self.get_computers(), check_delegation)


# --- Check with escalation path lookup ---
#
# from checks.core import Check, check
#
# @check(risk="Critical", category="User with Path to Domain Admin",
#        entity="user", data=["users", "escalation_paths"],
#        display="escalation_paths")
# class UserEscalationPathCheck(Check):
#
#     def execute(self):
#         def check_path(user):
#             if self.has_escalation_path(user.get('sid')):
#                 return self.finding("")
#             return None
#
#         return self.process_entity_results(self.get_users(), check_path)


# --- Platform check with DataSource (MSSQL/SCCM/OpenGraph) ---
#
# from checks.core import Check, check
# from checks.core.platform_mixins import MSSQLDomainMixin
#
# @check(risk="High", category="MSSQL Example Finding",
#        entity="computer", data=[], requires=["mssql"])
# class MSSQLExampleCheck(MSSQLDomainMixin, Check):
#
#     def execute(self):
#         rows = self.query("""
#             MATCH (s:MSSQL_Server)
#             WHERE s.some_property = true
#         """ + self._server_domain_condition('s') + """
#             RETURN s.name AS name, s.objectid AS objectid
#         """, name="mssql_example")
#         if not rows:
#             return {}
#         results = {}
#         for row in rows:
#             results[row['objectid']] = self.finding(row['name'])
#         return results


# --- ADCS template check ---
#
# from checks.core import check
# from checks.adcs_base import ADCSCheck
#
# @check(risk="High", category="ESC Example — Template Misconfiguration")
# class ESCExampleCheck(ADCSCheck):
#
#     def execute(self):
#         if not self.neo4j_data:
#             return {}
#         target_groups = self._get_target_groups()
#         if not target_groups:
#             return {}
#         rows = self._query_templates("""
#             MATCH (g:Group)-[:Enroll]->(t:CertTemplate)-[:PublishedTo]->(ca:EnterpriseCA)
#             WHERE t.some_flag = true
#               AND g.name IN $target_groups
#             RETURN t.name AS template, ca.caname AS ca_name,
#                    ca.dnshostname AS ca_host,
#                    collect(DISTINCT g.name) AS abusers
#             ORDER BY template
#         """, {'target_groups': target_groups})
#         return self._format_results(rows) if rows else {}
