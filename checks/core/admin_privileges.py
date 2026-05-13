from .sid_mapper import SidMapper

class AdminPrivilegesHandler:
    def __init__(self, account_analysis, sid_mapper=None):
        self.account_analysis = account_analysis
        self.sid_mapper = sid_mapper or SidMapper(account_analysis=account_analysis)

    def is_admin(self, sid_or_username):
        if not self.account_analysis:
            return False
        username = self.sid_mapper.get_username_from_sid_or_name(sid_or_username)
        if not username:
            return False
        if hasattr(self.account_analysis, 'user_details_mapping'):
            user_data = self.account_analysis.user_details_mapping.get(username, {})
            if isinstance(user_data, dict):
                return user_data.get('isAdmin', False)
        return False


