from checks.core import Check, check

@check(risk="High", category="User with Unconstrained Delegation",
       entity="user", data=["users"])
class UserUnconstrainedDelegationCheck(Check):

    def execute(self):
        users = self.get_users()
        if not users:
            return {}

        def check_unconstrained(user):
            if user.get('unconstrainedDelegation') is True:
                return self.finding()
            return None

        return self.process_entity_results(users, check_unconstrained)
