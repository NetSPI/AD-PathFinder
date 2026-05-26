from checks.core import Check, check


@check(risk="High", category="Non-admin AS-REP Roastable with Weak Password",
       entity="user", data=["users", "weak_password", "admin_privileges"])
class NonAdminAsrepRoastableWeakCheck(Check):

    def execute(self):
        def check_non_admin_asrep_weak(user):
            if (not self.is_admin(user) and
                user.get('asrepRoastable', False) and
                self.has_weak_password(user)):
                return self.finding()
            return None

        return self.process_entity_results(self.get_users(), check_non_admin_asrep_weak)
