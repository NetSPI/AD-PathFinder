from checks.core import Check, check


@check(risk="Critical", category="User with Weak Password and Constrained Delegation",
       entity="user", data=["users", "weak_password"])
class UserWeakPasswordConstrainedDelegationCheck(Check):

    def execute(self):
        def check_weak_password_constrained_delegation(user):
            delegation_info = user.get('constrainedDelegation')
            if not isinstance(delegation_info, list) or not delegation_info:
                return None
            if not self.has_weak_password(user):
                return None
            delegation_str = ", ".join(delegation_info)
            return self.finding(f"Constrained Delegation: {delegation_str}")

        return self.process_entity_results(self.get_users(), check_weak_password_constrained_delegation)
