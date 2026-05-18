from checks.core import Check, check


@check(risk="Critical", category="Kerberoastable with Admin privileges and Weak Password",
       entity="user", data=["users", "weak_password", "admin_privileges"])
class KerberoastableAdminWeakCheck(Check):
    
    def execute(self):
        def check_kerberoastable_admin_weak(user):
            is_kerberoastable = user.get('kerberoastable', False)
            is_user_admin = self.is_admin(user)
            has_weak_password = self.has_weak_password(user)
            
            if is_kerberoastable and is_user_admin and has_weak_password:
                return ""
            return None
        
        users = self.get_users()
        return self.process_entity_results(users, check_kerberoastable_admin_weak)