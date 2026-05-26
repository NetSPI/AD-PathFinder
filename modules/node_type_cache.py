#!/usr/bin/env python3

from typing import Any, List

# Keep both template labels: collectors/reporting paths can surface either
# spelling, and both canonicalize to CertTemplate for display.
AD_OBJECT_TYPES = [
    'User', 'Computer', 'Group', 'GPO', 'OU', 'Domain',
    'Container', 'CertTemplate', 'CertificateTemplate',
    'EnterpriseCA', 'RootCA', 'AIACA', 'NTAuthStore',
    'IssuancePolicy',
]

PLATFORM_OBJECT_TYPES = [
    'MSSQL_Server', 'MSSQL_Database', 'MSSQL_Login',
    'MSSQL_ServerRole', 'MSSQL_DatabaseRole', 'MSSQL_DatabaseUser',
    'MSSQL_Base', 'SCCM_Site', 'SCCM_Base',
]

# AD-only export used by the default report surface. Platform-aware callers
# must opt into ALL_OBJECT_TYPES or pass allow_platform=True.
OBJECT_TYPES = AD_OBJECT_TYPES
ALL_OBJECT_TYPES = AD_OBJECT_TYPES + PLATFORM_OBJECT_TYPES

BROAD_PLATFORM_LABELS = {'MSSQL_Base', 'SCCM_Base'}
METADATA_LABELS = {'Base', 'ADLocalGroup', 'LocalGroup'}
# Fallback OpenGraph stubs are non-reportable like metadata labels, but they
# are kept separate so the label's role is not mistaken for graph metadata.
STUB_LABELS = {'OpenGraph_Stub'}
_OBJECT_TYPE_ALIASES = {
    'CertificateTemplate': 'CertTemplate',
    'MSSQL_Base': 'MSSQL',
    'SCCM_Base': 'SCCM',
}
AD_REPORT_LABELS = tuple(AD_OBJECT_TYPES)
AD_REPORT_OBJECT_TYPES = tuple(
    dict.fromkeys(_OBJECT_TYPE_ALIASES.get(label, label) for label in AD_OBJECT_TYPES)
)
NON_REPORTABLE_NODE_LABELS = tuple(sorted(METADATA_LABELS | STUB_LABELS | BROAD_PLATFORM_LABELS))
REPORTABLE_NODE_LABELS = tuple(ALL_OBJECT_TYPES)
REPORTABLE_OBJECT_TYPES = tuple(
    dict.fromkeys(_OBJECT_TYPE_ALIASES.get(label, label) for label in ALL_OBJECT_TYPES)
)


def _canonical_object_type(label: str) -> str:
    return _OBJECT_TYPE_ALIASES.get(label, label)


def _is_informative_label(label: str) -> bool:
    return (
        isinstance(label, str)
        and label not in METADATA_LABELS
        and label not in STUB_LABELS
        and label not in BROAD_PLATFORM_LABELS
        and not label.startswith('Tag_')
    )


def _has_specific_platform_label(labels: List[str], broad_label: str) -> bool:
    prefix = broad_label.removesuffix('Base')
    return any(
        label != broad_label
        and label.startswith(prefix)
        and label in PLATFORM_OBJECT_TYPES
        for label in labels
    )


def extract_type_from_labels(labels: List[str], *, allow_platform: bool = False) -> str:
    if not labels:
        return 'Unknown'

    for ptype in AD_OBJECT_TYPES:
        if ptype in labels:
            return _canonical_object_type(ptype)

    if not allow_platform:
        return 'Unknown'

    for ptype in PLATFORM_OBJECT_TYPES:
        if ptype in labels:
            return _canonical_object_type(ptype)

    for label in labels:
        if _is_informative_label(label):
            return label

    return 'Unknown'


def extract_ad_report_type_from_labels(labels: List[str]) -> str:
    return extract_type_from_labels(labels, allow_platform=False)


def reportable_labels_from_labels(
    labels: List[str],
    *,
    allow_platform: bool = False,
) -> List[str]:
    if not labels:
        return []

    reportable = []
    for label in AD_OBJECT_TYPES:
        if label in labels:
            canonical = _canonical_object_type(label)
            if canonical not in reportable:
                reportable.append(canonical)
    if reportable:
        return reportable

    if not allow_platform:
        return []

    for label in PLATFORM_OBJECT_TYPES:
        if label in labels:
            if label in BROAD_PLATFORM_LABELS and _has_specific_platform_label(labels, label):
                continue
            canonical = _canonical_object_type(label)
            if canonical not in reportable:
                reportable.append(canonical)
    for label in labels:
        if _is_informative_label(label) and label not in reportable:
            reportable.append(label)
    return reportable


def ad_reportable_labels_from_labels(labels: List[str]) -> List[str]:
    return reportable_labels_from_labels(labels, allow_platform=False)


class NodeTypeCache:
    def __init__(self, neo4j_conn=None, *, allow_platform: bool = False):
        # AD-report rendering is the default; platform-aware callers opt in.
        self.neo4j_conn = neo4j_conn
        self.allow_platform = allow_platform
        self.type_cache = {}

    def _extract_type_from_labels(self, labels: List[str]) -> str:
        return extract_type_from_labels(labels, allow_platform=self.allow_platform)

    def get_node_type(self, identifier: str) -> str:
        if not identifier or not self.neo4j_conn:
            return 'Unknown'

        if identifier in self.type_cache:
            return self.type_cache[identifier]

        query = """
        MATCH (n)
        WHERE n.objectid = $identifier OR n.name = $identifier
        WITH n,
             CASE
                 WHEN any(label IN labels(n) WHERE label IN $ad_labels) THEN 0
                 WHEN any(label IN labels(n)
                          WHERE NOT label IN $metadata_labels
                          AND NOT label STARTS WITH 'Tag_') THEN 1
                 ELSE 2
             END AS label_rank,
             CASE WHEN n.objectid = $identifier THEN 0 ELSE 1 END AS id_rank
        ORDER BY label_rank, id_rank
        RETURN labels(n) as labels
        LIMIT 1
        """

        try:
            result = self.neo4j_conn.query(
                query,
                parameters={
                    'identifier': identifier,
                    'ad_labels': list(AD_REPORT_LABELS),
                    'metadata_labels': list(NON_REPORTABLE_NODE_LABELS),
                },
                name="get_node_type",
            )
            if result:
                labels = result[0].get('labels', [])
                node_type = extract_type_from_labels(
                    labels,
                    allow_platform=self.allow_platform,
                )
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
                node_type = extract_type_from_labels(
                    labels,
                    allow_platform=self.allow_platform,
                )
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
