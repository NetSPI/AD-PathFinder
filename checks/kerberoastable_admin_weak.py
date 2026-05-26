from checks.core import Check, check


@check(risk="Critical", category="Kerberoastable with Admin privileges and Weak Password",
       entity="user", data=["users", "weak_password", "admin_privileges"])
class KerberoastableAdminWeakCheck(Check):
    
    def execute(self):
        def check_kerberoastable_admin_weak(user):
            if user.get('kerberoastable', False) and self.is_admin(user) and self.has_weak_password(user):
                return self.finding()
            return None

        return self.process_entity_results(self.get_users(), check_kerberoastable_admin_weak)