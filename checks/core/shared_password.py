from .sid_mapper import SidMapper


class SharedPasswordHandler:
    def __init__(self, account_analysis, sid_mapper=None):
        self.account_analysis = account_analysis
        self.sid_mapper = sid_mapper or SidMapper(account_analysis=account_analysis)

    def has_shared_password(self, sid_or_username):
        if not self.account_analysis:
            return False
        username = self.sid_mapper.get_username_from_sid_or_name(sid_or_username)
        if not username:
            return False
        if hasattr(self.account_analysis, 'users_in_shared_accounts'):
            return username.lower() in self.account_analysis.users_in_shared_accounts
        return False
