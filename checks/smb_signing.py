from checks.core import Check, check


@check(risk="Medium", category="Computers with SMB Signing Disabled",
       entity="computer", data=["computers"])
class SMBSigningCheck(Check):
    
    def execute(self):
        computers = self.get_computers()
        if not computers:
            return {}

        def check_smb_signing(computer):
            if computer.get('smbsigning') is False:
                os = computer.get('operatingsystem', 'Unknown OS')
                return self.finding(f"({os})", inline=True)
            return None

        return self.process_entity_results(computers, check_smb_signing)