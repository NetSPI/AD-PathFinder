from checks.core import Check, check


@check(risk="Critical", category="Non-admin Users with Escalation Paths",
       entity="user",
       data=["users", "escalation_paths", "full_escalation_paths", "admin_privileges"],
       display="grouped_escalation_paths")
class UsersWithEscalationPathCheck(Check):

    def execute(self):
        users = self.get_users()
        return self.process_entity_results(users, self._check_user_with_path)

    def _check_user_with_path(self, user):
        if not self.has_escalation_path(user):
            return None
        if self.is_admin(user):
            return None
        return self.finding()
