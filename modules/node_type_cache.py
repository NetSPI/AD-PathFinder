#!/usr/bin/env python3

from typing import Any, List

OBJECT_TYPES = [
    'User', 'Computer', 'Group', 'GPO', 'OU', 'Domain',
    'Container', 'CertTemplate', 'CertificateTemplate',
    'EnterpriseCA', 'RootCA', 'AIACA', 'NTAuthStore',
    'IssuancePolicy', 'MSSQL_Server', 'MSSQL_Database',
    'MSSQL_Login', 'MSSQL_ServerRole', 'MSSQL_DatabaseRole'
]

METADATA_LABELS = {'Base', 'ADLocalGroup', 'LocalGroup'}


def extract_type_from_labels(labels: List[str]) -> str:
    if not labels:
        return 'Unknown'

    for ptype in OBJECT_TYPES:
        if ptype in labels:
            return ptype

    for label in labels:
        if label not in METADATA_LABELS and not label.startswith('Tag_'):
            return label

    return 'Unknown'


class NodeTypeCache:
    def __init__(self, neo4j_conn=None):
        self.neo4j_conn = neo4j_conn
        self.type_cache = {}

    def _extract_type_from_labels(self, labels: List[str]) -> str:
        return extract_type_from_labels(labels)

    def get_node_type(self, identifier: str) -> str:
        if not identifier or not self.neo4j_conn:
            return 'Unknown'

        if identifier in self.type_cache:
            return self.type_cache[identifier]

        query = """
        MATCH (n)
        WHERE n.objectid = $identifier OR n.name = $identifier
        RETURN labels(n) as labels
        LIMIT 1
        """

        try:
            result = self.neo4j_conn.query(query, parameters={'identifier': identifier}, name="get_node_type")
            if result:
                labels = result[0].get('labels', [])
                node_type = extract_type_from_labels(labels)
                self.type_cache[identifier] = node_type
                return node_type
        except Exception as e:
            print(f"Warning: node-type lookup failed for {identifier}: {e}")

        self.type_cache[identifier] = 'Unknown'
        return 'Unknown'

    def format_path_node(self, node_data: Any) -> str:
        if isinstance(node_data, dict):
            name = node_data.get('name') or ''
            labels = node_data.get('labels') or []

            if labels:
                node_type = extract_type_from_labels(labels)
            else:
                node_type = self.get_node_type(name)

            clean_name = name.split('@')[0] if '@' in name else name
            return f"{clean_name} ({node_type})"

        elif isinstance(node_data, str):
            clean_name = node_data.split('@')[0] if '@' in node_data else node_data
            node_type = self.get_node_type(node_data)

            if node_type != 'Unknown':
                return f"{clean_name} ({node_type})"
            return clean_name

        return str(node_data)
