import pytest

from modules.node_type_cache import (
    AD_REPORT_LABELS,
    NON_REPORTABLE_NODE_LABELS,
    NodeTypeCache,
    ad_reportable_labels_from_labels,
    extract_ad_report_type_from_labels,
    extract_type_from_labels,
    reportable_labels_from_labels,
)


class RecordingConnection:
    def __init__(self, rows):
        self.rows = rows
        self.queries = []

    def query(self, query, parameters=None, name=None):
        self.queries.append((query, parameters, name))
        return self.rows


@pytest.mark.parametrize(
    ("labels", "expected"),
    [
        (["Base", "User", "MSSQL_Login"], "User"),
        (["Base", "Computer"], "Computer"),
        (["CertificateTemplate", "Base"], "CertTemplate"),
        (["MSSQL_Server", "Base"], "MSSQL_Server"),
        (["SCCM_Site"], "SCCM_Site"),
        (["Base", "SCCM_Base"], "SCCM"),
        (["MSSQL_Base"], "MSSQL"),
        (["Base", "SCCM_Base", "SCCM_Site"], "SCCM_Site"),
        (["OpenGraph_Stub"], "Unknown"),
        (["Jenkins_Server"], "Jenkins_Server"),
        (["Base"], "Unknown"),
    ],
)
def test_extract_type_from_labels_uses_informative_non_metadata_labels_when_platform_enabled(labels, expected):
    assert extract_type_from_labels(labels, allow_platform=True) == expected


def test_extract_type_from_labels_defaults_to_ad_report_policy():
    assert extract_type_from_labels(["Base", "MSSQL_Server"]) == "Unknown"
    assert extract_type_from_labels(["Jenkins_Server"]) == "Unknown"


def test_ad_report_type_resolver_suppresses_plugin_only_labels():
    assert extract_ad_report_type_from_labels(["Base", "MSSQL_Server"]) == "Unknown"
    assert extract_ad_report_type_from_labels(["Base", "SCCM_Site"]) == "Unknown"
    assert extract_ad_report_type_from_labels(["Jenkins_Server"]) == "Unknown"
    assert extract_ad_report_type_from_labels(["Base", "Group", "SCCM_Site"]) == "Group"


def test_reportable_labels_from_labels_prefers_ad_labels_when_present():
    assert reportable_labels_from_labels(
        ["Base", "MSSQL_Login", "Group", "SCCM_Site", "CertificateTemplate"]
    ) == ["Group", "CertTemplate"]


def test_reportable_labels_from_labels_uses_plugin_or_custom_labels_without_ad():
    assert reportable_labels_from_labels(
        ["Base", "MSSQL_Login", "SCCM_Site", "Jenkins_Server", "OpenGraph_Stub"],
        allow_platform=True,
    ) == ["MSSQL_Login", "SCCM_Site", "Jenkins_Server"]


def test_reportable_labels_from_labels_canonicalises_broad_platform_base_labels():
    assert reportable_labels_from_labels(
        ["Base", "MSSQL_Base", "SCCM_Base", "SCCM_Site"],
        allow_platform=True,
    ) == ["MSSQL", "SCCM_Site"]


def test_reportable_labels_from_labels_defaults_to_ad_report_policy():
    assert reportable_labels_from_labels(["Base", "MSSQL_Login", "SCCM_Site"]) == []


def test_ad_reportable_labels_from_labels_drops_plugin_only_labels():
    assert ad_reportable_labels_from_labels(
        ["Base", "MSSQL_Login", "SCCM_Site", "Jenkins_Server", "OpenGraph_Stub"]
    ) == []
    assert ad_reportable_labels_from_labels(
        ["Base", "MSSQL_Login", "User", "SCCM_Site"]
    ) == ["User"]


def test_node_type_cache_defaults_to_ad_report_policy():
    assert NodeTypeCache()._extract_type_from_labels(["MSSQL_Server"]) == "Unknown"
    assert (
        NodeTypeCache().format_path_node(
            {"name": "sql01.example.local", "labels": ["Base", "MSSQL_Server"]}
        )
        == "sql01.example.local (Unknown)"
    )
    assert (
        NodeTypeCache(allow_platform=True)._extract_type_from_labels(["MSSQL_Server"])
        == "MSSQL_Server"
    )


def test_get_node_type_uses_reportable_label_preference_query():
    conn = RecordingConnection([{"labels": ["Base", "User"]}])
    cache = NodeTypeCache(conn)

    assert cache.get_node_type("S-1-5-21-example-1105") == "User"

    query, parameters, name = conn.queries[0]
    assert name == "get_node_type"
    assert "ORDER BY label_rank, id_rank" in query
    assert parameters["ad_labels"] == list(AD_REPORT_LABELS)
    assert parameters["metadata_labels"] == list(NON_REPORTABLE_NODE_LABELS)
