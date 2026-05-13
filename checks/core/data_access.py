from .constants import DataTypes, DataAccessConfig

class DataAccessLayer:
    def __init__(self, neo4j_data, shared_cache=None):
        self.neo4j_data = neo4j_data
        self.cache = shared_cache if shared_cache is not None else {}

    def _build_fetch_method_name(self, entity_type):
        if entity_type in DataAccessConfig.SPECIAL_METHODS:
            return DataAccessConfig.SPECIAL_METHODS[entity_type]
        return DataAccessConfig.METHOD_TEMPLATE.format(entity_type)

    def get_entity_data(self, entity_type):
        if entity_type not in self.cache:
            valid_types = {DataTypes.COMPUTERS, DataTypes.USERS,
                          DataTypes.ENTERPRISE_CAS, DataTypes.BAD_SUCCESSOR_OU_PRIVILEGES}
            if entity_type not in valid_types:
                raise ValueError(f"Unknown entity type: {entity_type}")

            fetch_method_name = self._build_fetch_method_name(entity_type)
            if hasattr(self.neo4j_data, fetch_method_name):
                fetch_method = getattr(self.neo4j_data, fetch_method_name)
                self.cache[entity_type] = fetch_method()
            else:
                raise ValueError(f"Unknown entity type: {entity_type} (method: {fetch_method_name})")
        return self.cache[entity_type]

    def get_computers(self):
        return self.get_entity_data(DataTypes.COMPUTERS)

    def get_users(self):
        return self.get_entity_data(DataTypes.USERS)

    def get_enterprise_cas(self):
        return self.get_entity_data(DataTypes.ENTERPRISE_CAS)

    def get_bad_successor_ou_privileges(self):
        return self.get_entity_data(DataTypes.BAD_SUCCESSOR_OU_PRIVILEGES)

    def get_escalation_paths(self):
        return self.cache.get(DataTypes.ESCALATION_PATHS, {})

    def has_escalation_path(self, entity_identifier):
        escalation_data = self.get_escalation_paths()
        if hasattr(entity_identifier, 'get'):
            sid = entity_identifier.get('sid')
            if sid:
                return escalation_data.get(sid, False)
        return escalation_data.get(entity_identifier, False)

