from checks.core import Check, check


@check(risk="High", category="Computers with Escalation Paths",
       entity="computer",
       data=["computers", "escalation_paths", "full_escalation_paths"],
       display="grouped_escalation_paths")
class ComputersWithEscalationPathCheck(Check):

    def execute(self):
        computers = self.get_computers()
        return self.process_entity_results(computers, self._check_computer_with_path)

    def _check_computer_with_path(self, computer):
        if self.has_escalation_path(computer):
            return self.finding()
        return None
