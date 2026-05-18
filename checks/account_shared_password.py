from checks.core import Check, check


@check(risk="Medium", category="Account with Shared Password",
       entity="user", data=["users"])
class AccountSharedPasswordCheck(Check):

    def execute(self):
        def check_shared_password(user):
            if self.has_shared_password(user):
                return self.finding()
            return None

        return self.process_entity_results(self.get_users(), check_shared_password)
