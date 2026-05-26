from checks.core import Check, check

@check(risk="High", category="Computer with Unconstrained Delegation",
       entity="computer", data=["computers"])
class ComputerUnconstrainedDelegationCheck(Check):

    def execute(self):
        def check_unconstrained_delegation(computer):
            if computer.get('unconstrainedDelegation') is True:
                return self.finding()
            return None

        return self.process_entity_results(self.get_computers(), check_unconstrained_delegation)
