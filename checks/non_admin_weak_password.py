from checks.core import Check, check


@check(risk="Medium", category="Non-admin with Weak Password",
       entity="user", data=["users", "weak_password", "admin_privileges"])
class NonAdminWeakPasswordCheck(Check):

    def execute(self):
        def check_non_admin_weak_password(user):
            if not self.is_admin(user) and self.has_weak_password(user):
                return self.finding()
            return None

        return self.process_entity_results(self.get_users(), check_non_admin_weak_password)
