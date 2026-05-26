from checks.core import Check, check


@check(risk="Critical", category="Admin with Weak Password",
       entity="user", data=["users", "weak_password"])
class AdminWeakPasswordCheck(Check):

    def execute(self):
        def check_admin_weak_password(user):
            if self.is_admin(user) and self.has_weak_password(user):
                return self.finding()
            return None

        return self.process_entity_results(self.get_users(), check_admin_weak_password)
