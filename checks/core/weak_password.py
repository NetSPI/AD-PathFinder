from .sid_mapper import SidMapper

class WeakPasswordHandler:
    def __init__(self, account_analysis, sid_mapper=None):
        self.account_analysis = account_analysis
        self.sid_mapper = sid_mapper or SidMapper(account_analysis=account_analysis)

    def has_weak_password(self, sid_or_username):
        if not self.account_analysis:
            return False
        username = self.sid_mapper.get_username_from_sid_or_name(sid_or_username)
        if not username:
            return False
        return self.account_analysis._has_weak_password(username)

    def get_password_display(self, sid_or_username):
        username = self.sid_mapper.get_username_from_sid_or_name(sid_or_username)
        if not username or not self.has_weak_password(username):
            return None
        password_display = "Cracked"
        if self.account_analysis.output_format == 'unsafe':
            password_display = self.account_analysis.cracked_accounts.get(username.lower(), "Cracked")
            if password_display == '':
                password_display = "(blank)"
        return password_display

