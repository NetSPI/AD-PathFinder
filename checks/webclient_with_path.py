from checks.core import Check, check


@check(risk="High", category="Computers with WebClient and Escalation Paths",
       entity="computer", data=["computers", "escalation_paths"],
       display="escalation_paths")
class WebClientComputerCheck(Check):

    def execute(self):
        computers = self.get_computers()
        if not computers:
            return {}

        def check_webclient_with_path(computer):
            if computer.get('webclientrunning', False) is True and self.has_escalation_path(computer):
                os_info = computer.get('operatingsystem', 'Unknown OS')
                return self.finding(f"WebClient Running + Has Escalation Path ({os_info})")
            return None

        return self.process_entity_results(computers, check_webclient_with_path)