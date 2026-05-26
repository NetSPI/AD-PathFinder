from checks.core import Check, check

@check(risk="Medium", category="Computer with Constrained Delegation",
       entity="computer", data=["computers"])
class ComputerConstrainedDelegationCheck(Check):

    def execute(self):
        def check_constrained_delegation(computer):
            delegation_info = computer.get('constrainedDelegation')
            if isinstance(delegation_info, list) and delegation_info:
                delegation_str = ", ".join(delegation_info)
                return self.finding(f"Constrained Delegation: {delegation_str}")
            return None

        return self.process_entity_results(self.get_computers(), check_constrained_delegation)
