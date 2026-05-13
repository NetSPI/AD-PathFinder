from checks.core import Check, check


@check(risk="High", category="Computers with SMB Signing Disabled and Escalation Paths",
       entity="computer", data=["computers", "escalation_paths"],
       display="escalation_paths")
class WeakComputerConfigCheck(Check):

    def execute(self):
        computers = self.get_computers()
        if not computers:
            return {}

        def check_smb_signing_with_path(computer):
            if computer.get('smbsigning') is False and self.has_escalation_path(computer):
                os_info = computer.get('operatingsystem', 'Unknown OS')
                return self.finding(f"SMB Signing Disabled + Has Escalation Path ({os_info})")
            return None

        return self.process_entity_results(computers, check_smb_signing_with_path)