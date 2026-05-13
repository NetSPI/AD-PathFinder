from checks.core import Check, check
from checks.core.admin_rights_helper import AdminRightsHelper


@check(risk="High", category="Non-admin User has Admin Rights on a Computer",
       entity="user", data=["users", "admin_privileges"])
class NonAdminComputerRightsCheck(AdminRightsHelper, Check):

    def execute(self):
        return self.process_entity_results(self.get_users(), self._check_admin_rights)

    def _check_admin_rights(self, user):
        if self.is_admin(user):
            return None
        admin_records = self._get_entity_admin_records(user)
        return self._create_admin_vulnerability_result(admin_records, entity_type='user')
