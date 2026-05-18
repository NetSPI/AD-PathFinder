from checks.core import Check, check


@check(risk="Critical", category="Computer has Weak Password",
       entity="computer", data=["computers", "weak_password"])
class ComputerWeakPasswordCheck(Check):

    def execute(self):
        computers = self.get_computers()
        return self.process_entity_results(computers, self._check_computer_weak_password)

    def _check_computer_weak_password(self, computer):
        if not computer or not computer.get('sid'):
            return None

        sid = computer.get('sid')

        if not self.has_weak_password(sid):
            return None

        return self.finding()
