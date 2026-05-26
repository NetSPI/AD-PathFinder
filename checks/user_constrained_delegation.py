from checks.core import Check, check

@check(risk="High", category="User with Constrained Delegation",
       entity="user", data=["users"])
class UserConstrainedDelegationCheck(Check):

    def execute(self):
        def check_constrained_delegation(user):
            delegation_info = user.get('constrainedDelegation')
            if isinstance(delegation_info, list) and delegation_info:
                delegation_str = ", ".join(delegation_info)
                return self.finding(f"Constrained Delegation: {delegation_str}")
            return None

        return self.process_entity_results(self.get_users(), check_constrained_delegation)
