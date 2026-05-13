from .constants import is_sid

class SidMapper:
    def __init__(self, neo4j_data=None, account_analysis=None, shared_cache=None):
        self.neo4j_data = neo4j_data
        self.account_analysis = account_analysis
        self.cache = shared_cache if shared_cache is not None else {}
        self._sid_to_username_cache = {}
        if not self.neo4j_data and self.account_analysis:
            self.neo4j_data = getattr(account_analysis, 'neo4j_data', None)

    def get_username_from_sid_or_name(self, sid_or_username):
        if not sid_or_username:
            return None
        if not is_sid(sid_or_username):
            return sid_or_username
        if self.neo4j_data and hasattr(self.neo4j_data, 'sid_to_username'):
            return self.neo4j_data.sid_to_username.get(sid_or_username)
        return None

    def get_display_name(self, identifier):
        if not identifier:
            return identifier
        display_name = identifier
        if is_sid(identifier) or '-S-1-' in identifier:
            if 'computers' in self.cache:
                for computer in self.cache['computers']:
                    if computer.get('sid') == identifier:
                        computer_name = computer.get('name')
                        if computer_name and '.' in computer_name:
                            display_name = computer_name.upper()
                            break
            if display_name == identifier:
                if self.neo4j_data and hasattr(self.neo4j_data, 'sid_to_username'):
                    name = self.neo4j_data.sid_to_username.get(identifier)
                    if name:
                        display_name = name.upper()
        else:
            display_name = identifier if '://' in identifier else identifier.upper()
        return display_name

    def extract_sid(self, entity_identifier):
        if hasattr(entity_identifier, 'get'):
            return entity_identifier.get('sid')
        elif isinstance(entity_identifier, str):
            if is_sid(entity_identifier):
                return entity_identifier
            else:
                return None
        return None