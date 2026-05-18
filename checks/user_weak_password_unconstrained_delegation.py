from checks.core import Check, check


@check(risk="Critical", category="User with Weak Password and Unconstrained Delegation",
       entity="user", data=["users", "weak_password"])
class UserWeakPasswordUnconstrainedDelegationCheck(Check):

    def execute(self):
        def check_weak_password_unconstrained_delegation(user):
            if user.get('unconstrainedDelegation') is not True:
                return None
            if not self.has_weak_password(user):
                return None
            return self.finding()

        return self.process_entity_results(self.get_users(), check_weak_password_unconstrained_delegation)
