from checks.core import Check, check
from checks.core.admin_rights_helper import AdminRightsHelper


@check(risk="High", category="Computer has Admin Rights from Another Computer",
       entity="computer", data=["computers", "admin_privileges"])
class ComputerAdminRightsCheck(AdminRightsHelper, Check):

    def execute(self):
        return self.process_entity_results(self.get_computers(), self._check_admin_rights)

    def _check_admin_rights(self, computer):
        admin_records = self._get_entity_admin_records(computer)
        return self._create_admin_vulnerability_result(admin_records, entity_type='computer')
