from .constants import EntityTypes
from .admin_paths import AdminDisplayStrategy


class AdminRightsHelper:

    def _get_entity_admin_records(self, entity):
        if not entity or not entity.get('sid'):
            return []
        entity_sid = self._extract_identifier(entity)
        if not entity_sid:
            return []
        return self._load_admin_paths().get(entity_sid, [])

    def _load_admin_paths(self):
        if getattr(self, '_admin_paths_cache', None) is not None:
            return self._admin_paths_cache
        self._admin_paths_cache = {}
        method_name = ('get_computer_admin_paths' if self.ENTITY_TYPE == EntityTypes.COMPUTER
                       else 'get_user_to_computer_admin_paths')
        for record in getattr(self.neo4j_data, method_name)():
            source_sid = record.get('SourceSID')
            if source_sid:
                if source_sid not in self._admin_paths_cache:
                    self._admin_paths_cache[source_sid] = []
                self._admin_paths_cache[source_sid].append(record)
        return self._admin_paths_cache

    def _create_admin_vulnerability_result(self, admin_records, entity_type):
        if not admin_records:
            return None
        display_info = AdminDisplayStrategy.format_admin_display(admin_records, entity_type)
        if display_info['format_type'] == 'hierarchical':
            return self.finding(display_info['description'])
        else:
            return self.finding(display_info['description'], inline=True)
