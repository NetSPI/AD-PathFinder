from checks.core import Check, check


@check(risk="High", category="Non-admin Kerberoastable with Weak Password",
       entity="user", data=["users", "weak_password", "admin_privileges"])
class NonAdminKerberoastableWeakCheck(Check):

    def execute(self):
        def check_non_admin_kerberoastable_weak(user):
            if (not self.is_admin(user) and
                user.get('kerberoastable', False) and
                self.has_weak_password(user) and
                not user.get('is_computer', False)):
                return self.finding()
            return None

        return self.process_entity_results(self.get_users(), check_non_admin_kerberoastable_weak)
