import importlib
import json
import zipfile
from pathlib import Path

import pytest

from modules.BloodhoundImporter import (
    BloodhoundImporter,
    _normalise_neo4j_properties,
)
from modules.collectors.mssqlhound import _mssql_identity
from modules.opengraph_contracts import (
    OpenGraphRequirement,
    OpenGraphRequirementWarning,
    RequiredRelationship,
)
from modules.opengraph_collectors import CollectorManifest
from modules.opengraph_identifiers import safe_cypher_identifier


class RecordingConnection:
    def __init__(self, responses=None):
        self.queries = []
        self.responses = list(responses or [])

    def query(self, query, parameters=None):
        self.queries.append((query, parameters))
        if self.responses:
            return self.responses.pop(0)
        return []


def _write_json(tmp_path, name, data):
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


class NoSideEffectImporter(BloodhoundImporter):
    def __init__(self, neo4j_conn):
        super().__init__(neo4j_conn)
        self.authenticated = False

    def _authenticate(self):
        self.authenticated = True
        raise AssertionError("validation should run before authentication")


class NoDedupeOrSideEffectImporter(NoSideEffectImporter):
    def __init__(self, neo4j_conn):
        super().__init__(neo4j_conn)
        self.dedupe_called = False

    def _deduplicate_by_identity(self, entries):
        self.dedupe_called = True
        raise AssertionError("validation should run before identity dedupe")


def _opengraph(source_kind, nodes, edges=None):
    return {
        "metadata": {"source_kind": source_kind},
        "graph": {"nodes": nodes, "edges": edges or []},
    }


@pytest.mark.parametrize(
    ("name", "data", "expected"),
    [
        ("sharphound.json", {"data": []}, "sharphound"),
        (
            "seed.json",
            _opengraph(
                "Anything",
                [{"id": "seed", "kinds": ["IgnoreMe"], "properties": {}}],
            ),
            "seed",
        ),
        (
            "groups.json",
            _opengraph(
                "Groups",
                [{"id": "S-1-1", "kinds": ["Base", "Group"], "properties": {}}],
            ),
            "ad_companion",
        ),
        (
            "jenkins.json",
            _opengraph(
                "Jenkins",
                [{"id": "jenkins-1", "kinds": ["Base", "Jenkins_Server"], "properties": {}}],
            ),
            "opengraph",
        ),
        (
            "mixed.json",
            _opengraph(
                "SCCM",
                [
                    {"id": "sql-1", "kinds": ["Base", "MSSQL_Server"], "properties": {}},
                    {"id": "site-1", "kinds": ["Base", "SCCM_Site"], "properties": {}},
                ],
            ),
            "opengraph",
        ),
        (
            "base-only.json",
            _opengraph(
                "Opaque",
                [{"id": "opaque-1", "kinds": ["Base"], "properties": {}}],
            ),
            "opengraph",
        ),
        (
            "mixed-ad-base-only.json",
            _opengraph(
                "Groups",
                [
                    {"id": "S-1-1", "kinds": ["Base", "Group"], "properties": {}},
                    {"id": "S-1-2", "kinds": ["Base"], "properties": {}},
                ],
            ),
            "ad_companion",
        ),
    ],
)
def test_classify_json_file_structural(tmp_path, name, data, expected):
    importer = BloodhoundImporter(None)
    path = _write_json(tmp_path, name, data)

    category, parsed = importer._classify_json_file(path)

    assert category == expected
    if expected == "sharphound":
        assert parsed is None
    else:
        assert parsed == data


def test_classify_malformed_graph_as_opengraph_for_validation(tmp_path):
    importer = BloodhoundImporter(None)
    data = {"graph": []}
    path = _write_json(tmp_path, "bad-plugin.json", data)

    category, parsed = importer._classify_json_file(path)

    assert category == "opengraph"
    assert parsed == data


@pytest.mark.parametrize(
    "data",
    [
        {"metadata": {"source_kind": "Jenkins_Base"}},
        {"$schema": "https://example.test/opengraph.schema.json"},
    ],
)
def test_classify_missing_graph_opengraph_sentinels_for_validation(tmp_path, data):
    importer = BloodhoundImporter(None)
    path = _write_json(tmp_path, "bad-plugin.json", data)

    category, parsed = importer._classify_json_file(path)

    assert category == "opengraph"
    assert parsed == data


@pytest.mark.parametrize(
    "data",
    [
        {"$schema": "https://json-schema.org/draft/2020-12/schema"},
        {"$schema": True},
    ],
)
def test_classify_missing_graph_generic_schema_as_sharphound(tmp_path, data):
    importer = BloodhoundImporter(None)
    path = _write_json(tmp_path, "schema.json", data)

    category, parsed = importer._classify_json_file(path)

    assert category == "sharphound"
    assert parsed is None


def test_extract_zip_discovers_nested_json_files(tmp_path):
    importer = BloodhoundImporter(None)
    zip_path = tmp_path / "plugin.zip"
    extract_dir = tmp_path / "extract"
    extract_dir.mkdir()
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("PluginName/data/opengraph.json", "{}")
        archive.writestr("PluginName/notes.txt", "not json")

    json_files = importer._extract_zip(zip_path, extract_dir)

    assert [path.relative_to(extract_dir).as_posix() for path in json_files] == [
        "PluginName/data/opengraph.json"
    ]


def test_filter_companion_properties_returns_dict_and_keeps_only_additive():
    importer = BloodhoundImporter(None)
    data = _opengraph(
        "Groups",
        [
            {
                "id": "S-1-1",
                "kinds": ["Base", "User"],
                "properties": {
                    "name": "ALICE@EXAMPLE.LOCAL",
                    "objectid": "wrong",
                    "SMBSigningRequired": True,
                    "SCCMClient": "Enabled",
                },
            },
            {
                "id": "S-1-2",
                "kinds": ["Base", "Group"],
                "properties": {"name": "DOMAIN ADMINS@EXAMPLE.LOCAL"},
            },
        ],
    )

    manifest = importer._select_collector_manifest(data)
    filtered = importer._filter_companion_properties(data, manifest)

    assert isinstance(filtered, dict)
    assert filtered is data
    assert filtered["graph"]["nodes"] == [
        {
            "id": "S-1-1",
            "kinds": ["Base", "User"],
            "properties": {
                "SMBSigningRequired": True,
                "SCCMClient": "Enabled",
            },
        }
    ]


def test_filter_companion_properties_keeps_empty_endpoint_nodes_for_edges():
    importer = BloodhoundImporter(None)
    edge = {
        "kind": "Custom_AD_Link",
        "start": {"value": "S-1-1"},
        "end": {"value": "S-1-2"},
        "properties": {},
    }
    data = _opengraph(
        "Groups",
        [
            {
                "id": "S-1-1",
                "kinds": ["Base", "User"],
                "properties": {"name": "ALICE@EXAMPLE.LOCAL"},
            },
            {
                "id": "S-1-2",
                "kinds": ["Base", "Group"],
                "properties": {"name": "DOMAIN ADMINS@EXAMPLE.LOCAL"},
            },
        ],
        [edge],
    )

    manifest = importer._select_collector_manifest(data)
    filtered = importer._filter_companion_properties(data, manifest)

    assert filtered is data
    assert filtered["graph"]["nodes"] == [
        {"id": "S-1-1", "kinds": ["Base", "User"], "properties": {}},
        {"id": "S-1-2", "kinds": ["Base", "Group"], "properties": {}},
    ]
    assert filtered["graph"]["edges"] == [edge]


def test_filter_companion_properties_uses_owned_kinds_for_filter_scope():
    importer = BloodhoundImporter(None)
    manifest = CollectorManifest(
        source_kind="FakeCompanion",
        principal_kinds=("Fake_User",),
        owned_kinds=("Fake_User", "Fake_Device"),
        merge_strategy="companion_additive",
        allowed_companion_properties=("FakeAllowed",),
    )
    data = _opengraph(
        "FakeCompanion",
        [
            {
                "id": "device-1",
                "kinds": ["Base", "Fake_Device"],
                "properties": {
                    "FakeAllowed": True,
                    "name": "DROP",
                },
            },
            {
                "id": "external-1",
                "kinds": ["Base", "External_Node"],
                "properties": {
                    "name": "KEEP",
                },
            },
        ],
    )

    filtered = importer._filter_companion_properties(data, manifest)

    assert filtered["graph"]["nodes"] == [
        {
            "id": "device-1",
            "kinds": ["Base", "Fake_Device"],
            "properties": {"FakeAllowed": True},
        },
        {
            "id": "external-1",
            "kinds": ["Base", "External_Node"],
            "properties": {"name": "KEEP"},
        },
    ]


def test_ad_companion_node_merges_on_specific_ad_label():
    conn = RecordingConnection()
    importer = BloodhoundImporter(conn)
    node = {
        "id": "S-1-1",
        "kinds": ["Base", "Group"],
        "properties": {"SMBSigningRequired": True},
    }
    manifest = importer._select_collector_manifest(_opengraph("Groups", [node]))

    importer._import_opengraph_node(
        node,
        "groups.json",
        "ad_companion",
        companion_manifest=manifest,
    )

    query, parameters = conn.queries[0]
    assert "MATCH (n:`Group` {objectid: $objectid})" in query
    assert "MATCH (n:`Base`" not in query
    assert parameters["objectid"] == "S-1-1"


def test_ad_companion_logs_when_sharphound_principal_is_missing(capsys):
    conn = RecordingConnection(responses=[[]])
    importer = BloodhoundImporter(conn)
    data = _opengraph(
        "Groups",
        [
            {
                "id": "S-1-1",
                "kinds": ["Base", "Group"],
                "properties": {"SMBSigningRequired": True},
            },
        ],
    )

    importer._import_opengraph_files_directly([("groups.json", data, "ad_companion")])

    output = capsys.readouterr().out
    assert "AD companion groups.json: skipped 1 node(s)" in output
    assert "SharpHound principal was not found" in output
    assert "S-1-1" in output


def test_generic_opengraph_node_uses_label_constrained_merge():
    conn = RecordingConnection()
    importer = BloodhoundImporter(conn)

    importer._import_opengraph_node(
        {
            "id": "jenkins-1",
            "kinds": ["Base", "Jenkins_Server"],
            "properties": {"name": "ci.example.local"},
        },
        "jenkins.json",
        "opengraph",
    )

    query, parameters = conn.queries[0]
    assert "MERGE (n:`Jenkins_Server` {objectid: $objectid})" in query
    assert "SET n:`Base`" not in query
    assert parameters["objectid"] == "jenkins-1"


def test_generic_opengraph_node_keeps_specific_extra_labels():
    conn = RecordingConnection()
    importer = BloodhoundImporter(conn)

    importer._import_opengraph_node(
        {
            "id": "jenkins-1",
            "kinds": ["Base", "Jenkins_Server", "Jenkins_Controller"],
            "properties": {},
        },
        "jenkins.json",
        "opengraph",
    )

    query, _ = conn.queries[0]
    assert "MERGE (n:`Jenkins_Server` {objectid: $objectid})" in query
    assert "SET n:`Jenkins_Controller`" in query
    assert "SET n:`Base`" not in query


def test_generic_opengraph_base_only_node_uses_stub_primary_label():
    conn = RecordingConnection()
    importer = BloodhoundImporter(conn)

    primary_label = importer._import_opengraph_node(
        {
            "id": "shared-object-id",
            "kinds": ["Base"],
            "properties": {"name": "opaque endpoint"},
        },
        "mixed.json",
        "opengraph",
    )

    query, parameters = conn.queries[0]
    assert primary_label == "OpenGraph_Stub"
    assert "MERGE (n:`OpenGraph_Stub` {objectid: $objectid})" in query
    assert "MERGE (n:`Base`" not in query
    assert "SET n:`Base`" not in query
    assert parameters["objectid"] == "shared-object-id"


def test_opengraph_endpoint_stubs_use_source_kind_label():
    conn = RecordingConnection(responses=[[{"c": 0}], [{"c": 1}]])
    importer = BloodhoundImporter(conn)
    data = _opengraph(
        "Jenkins_Base",
        [],
        [
            {
                "kind": "Jenkins_AdminTo",
                "start": {"value": "jenkins-1"},
                "end": {"value": "S-1-1"},
                "properties": {},
            }
        ],
    )

    stub_labels = importer._import_opengraph_files_directly(
        [("jenkins.json", data, "opengraph")]
    )

    assert stub_labels == {"Jenkins_Base"}
    assert any("MERGE (n:`Jenkins_Base` {objectid: $objectid})" in q for q, _ in conn.queries)


def test_opengraph_endpoint_stubs_reject_invalid_source_kind_before_query():
    conn = RecordingConnection(responses=[[{"c": 0}], [{"c": 0}]])
    importer = BloodhoundImporter(conn)
    data = {
        "metadata": {"source_kind": "Jenkins-Base"},
        "graph": {
            "nodes": [],
            "edges": [
                {
                    "kind": "Jenkins_AdminTo",
                    "start": {"value": "jenkins-1"},
                    "end": {"value": "S-1-1"},
                    "properties": {},
                }
            ],
        },
    }

    with pytest.raises(ValueError, match="metadata\\.source_kind"):
        importer._import_opengraph_files_directly(
            [("jenkins.json", data, "opengraph")]
        )

    assert conn.queries == []


def test_opengraph_rejects_invalid_node_label_before_query():
    conn = RecordingConnection()
    importer = BloodhoundImporter(conn)
    data = _opengraph(
        "Jenkins_Base",
        [
            {
                "id": "jenkins-1",
                "kinds": ["Base", "Jenkins_Server"],
                "properties": {},
            },
            {
                "id": "jenkins-2",
                "kinds": ["Base", "Jenkins-Server"],
                "properties": {},
            },
        ],
    )

    with pytest.raises(ValueError, match="node 'jenkins-2' label"):
        importer._import_opengraph_files_directly(
            [("jenkins.json", data, "opengraph")]
        )

    assert conn.queries == []


def test_opengraph_rejects_invalid_edge_kind_before_query():
    conn = RecordingConnection()
    importer = BloodhoundImporter(conn)
    data = _opengraph(
        "Jenkins_Base",
        [
            {
                "id": "jenkins-1",
                "kinds": ["Base", "Jenkins_Server"],
                "properties": {},
            },
            {
                "id": "job-1",
                "kinds": ["Base", "Jenkins_Job"],
                "properties": {},
            },
        ],
        [
            {
                "kind": "Jenkins-Runs",
                "start": {"value": "jenkins-1"},
                "end": {"value": "job-1"},
                "properties": {},
            }
        ],
    )

    with pytest.raises(ValueError, match="edge 0 kind"):
        importer._import_opengraph_files_directly(
            [("jenkins.json", data, "opengraph")]
        )

    assert conn.queries == []


def test_opengraph_rejects_non_object_node_properties_before_query():
    conn = RecordingConnection()
    importer = BloodhoundImporter(conn)
    data = _opengraph(
        "Jenkins_Base",
        [
            {
                "id": "jenkins-1",
                "kinds": ["Base", "Jenkins_Server"],
                "properties": ["bad"],
            }
        ],
    )

    with pytest.raises(ValueError, match="node 'jenkins-1' properties must be an object"):
        importer._import_opengraph_files_directly(
            [("jenkins.json", data, "opengraph")]
        )

    assert conn.queries == []


@pytest.mark.parametrize("kinds", ["", None, False, 0, {}, ()])
def test_opengraph_rejects_falsey_non_list_kinds_before_query(kinds):
    conn = RecordingConnection()
    importer = BloodhoundImporter(conn)
    data = _opengraph(
        "Jenkins_Base",
        [
            {
                "id": "jenkins-1",
                "kinds": kinds,
                "properties": {},
            }
        ],
    )

    with pytest.raises(ValueError, match="node 'jenkins-1' kinds must be a list"):
        importer._import_opengraph_files_directly(
            [("jenkins.json", data, "opengraph")]
        )

    assert conn.queries == []


@pytest.mark.parametrize(
    "node",
    [
        {"id": "opaque-1", "properties": {"name": "opaque"}},
        {"id": "opaque-1", "kinds": [], "properties": {"name": "opaque"}},
    ],
)
def test_opengraph_missing_or_empty_kinds_uses_base_fallback(node):
    conn = RecordingConnection()
    importer = BloodhoundImporter(conn)
    data = _opengraph("Opaque", [node])

    importer._import_opengraph_files_directly([("opaque.json", data, "opengraph")])

    query, _ = conn.queries[0]
    assert "MERGE (n:`OpenGraph_Stub` {objectid: $objectid})" in query


def test_import_opengraph_node_rejects_non_list_kinds_direct_call():
    conn = RecordingConnection()
    importer = BloodhoundImporter(conn)

    with pytest.raises(ValueError, match="node 'jenkins-1' kinds must be a list"):
        importer._import_opengraph_node(
            {"id": "jenkins-1", "kinds": "", "properties": {}},
            "jenkins.json",
            "opengraph",
        )

    assert conn.queries == []


def test_opengraph_rejects_non_object_edge_properties_before_query():
    conn = RecordingConnection()
    importer = BloodhoundImporter(conn)
    data = _opengraph(
        "Jenkins_Base",
        [
            {
                "id": "jenkins-1",
                "kinds": ["Base", "Jenkins_Server"],
                "properties": {},
            },
            {
                "id": "job-1",
                "kinds": ["Base", "Jenkins_Job"],
                "properties": {},
            },
        ],
        [
            {
                "kind": "Jenkins_Runs",
                "start": {"value": "jenkins-1"},
                "end": {"value": "job-1"},
                "properties": "bad",
            }
        ],
    )

    with pytest.raises(ValueError, match="edge 0 properties must be an object"):
        importer._import_opengraph_files_directly(
            [("jenkins.json", data, "opengraph")]
        )

    assert conn.queries == []


def test_opengraph_edges_use_payload_node_labels_for_endpoint_matches():
    conn = RecordingConnection()
    importer = BloodhoundImporter(conn)
    data = _opengraph(
        "Jenkins_Base",
        [
            {
                "id": "shared-object-id",
                "kinds": ["Base", "Jenkins_Server"],
                "properties": {},
            },
            {
                "id": "job-1",
                "kinds": ["Base", "Jenkins_Job"],
                "properties": {},
            },
        ],
        [
            {
                "kind": "Jenkins_Runs",
                "start": {"value": "shared-object-id"},
                "end": {"value": "job-1"},
                "properties": {},
            }
        ],
    )

    stub_labels = importer._import_opengraph_files_directly(
        [("jenkins.json", data, "opengraph")]
    )

    edge_query = conn.queries[-1][0]
    assert stub_labels == set()
    assert "MATCH (start:`Jenkins_Server` {objectid: $start_id})" in edge_query
    assert "MATCH (end:`Jenkins_Job` {objectid: $end_id})" in edge_query
    assert "MATCH (start {objectid: $start_id})" not in edge_query
    assert "MATCH (end {objectid: $end_id})" not in edge_query


def test_opengraph_edges_can_match_endpoint_by_name_with_kind():
    conn = RecordingConnection()
    importer = BloodhoundImporter(conn)
    data = _opengraph(
        "Jenkins_Base",
        [
            {
                "id": "job-1",
                "kinds": ["Base", "Jenkins_Job"],
                "properties": {},
            }
        ],
        [
            {
                "kind": "Jenkins_AdminTo",
                "start": {
                    "match_by": "name",
                    "value": "ALICE@EXAMPLE.LOCAL",
                    "kind": "User",
                },
                "end": {"value": "job-1"},
                "properties": {},
            }
        ],
    )

    stub_labels = importer._import_opengraph_files_directly(
        [("jenkins.json", data, "opengraph")]
    )

    edge_query, edge_params = conn.queries[-1]
    assert stub_labels == set()
    assert "MATCH (start:`User`)" in edge_query
    assert "WHERE start.name = $start_name" in edge_query
    assert "MATCH (end:`Jenkins_Job` {objectid: $end_id})" in edge_query
    assert edge_params["start_name"] == "ALICE@EXAMPLE.LOCAL"
    assert edge_params["end_id"] == "job-1"


def test_opengraph_edges_can_match_endpoint_by_property_matchers():
    conn = RecordingConnection()
    importer = BloodhoundImporter(conn)
    data = _opengraph(
        "Jenkins_Base",
        [
            {
                "id": "job-1",
                "kinds": ["Base", "Jenkins_Job"],
                "properties": {},
            }
        ],
        [
            {
                "kind": "Jenkins_Owns",
                "start": {
                    "match_by": "property",
                    "kind": "Jenkins_User",
                    "property_matchers": [
                        {
                            "key": "email",
                            "operator": "equals",
                            "value": "dev@example.local",
                        }
                    ],
                },
                "end": {"value": "job-1"},
                "properties": {},
            }
        ],
    )

    importer._import_opengraph_files_directly([("jenkins.json", data, "opengraph")])

    edge_query, edge_params = conn.queries[-1]
    assert "MATCH (start:`Jenkins_User`)" in edge_query
    assert "start[matcher.key] = matcher.value" in edge_query
    assert edge_params["start_property_matchers"] == [
        {"key": "email", "operator": "equals", "value": "dev@example.local"}
    ]
    assert edge_params["end_id"] == "job-1"


@pytest.mark.parametrize(
    ("start", "expected_error"),
    [
        (
            {"match_by": "property", "value": "x", "property_matchers": []},
            "start\\.value is not supported",
        ),
        (
            {"match_by": "property"},
            "start\\.property_matchers must be a non-empty list",
        ),
        (
            {
                "match_by": "id",
                "value": "x",
                "property_matchers": [
                    {"key": "email", "operator": "equals", "value": "x"}
                ],
            },
            "start\\.property_matchers is only supported",
        ),
        (
            {"match_by": "name"},
            "start\\.value is required",
        ),
        (
            {"match_by": "bogus", "value": "x"},
            "start\\.match_by must be one of",
        ),
        (
            {
                "match_by": "property",
                "property_matchers": [
                    {"key": "email", "operator": "contains", "value": "x"}
                ],
            },
            "start\\.property_matchers\\[0\\]\\.operator must be 'equals'",
        ),
        (
            {"match_by": "id", "value": "x", "kind": "Bad-Kind"},
            "start\\.kind has unsupported identifier",
        ),
    ],
)
def test_opengraph_rejects_invalid_endpoint_matchers_before_query(
    start,
    expected_error,
):
    conn = RecordingConnection()
    importer = BloodhoundImporter(conn)
    data = _opengraph(
        "Jenkins_Base",
        [],
        [
            {
                "kind": "Jenkins_Runs",
                "start": start,
                "end": {"value": "job-1"},
                "properties": {},
            }
        ],
    )

    with pytest.raises(ValueError, match=expected_error):
        importer._import_opengraph_files_directly(
            [("jenkins.json", data, "opengraph")]
        )

    assert conn.queries == []


def test_import_warns_once_for_dropped_properties(capsys):
    conn = RecordingConnection()
    importer = BloodhoundImporter(conn)
    data = _opengraph(
        "Jenkins_Base",
        [
            {
                "id": "jenkins-1",
                "kinds": ["Base", "Jenkins_Server"],
                "properties": {
                    "name": "ci.example.local",
                    "meta": {"nested": "value"},
                    "nullable": None,
                    "mixed": ["ci", 1],
                },
            },
            {
                "id": "job-1",
                "kinds": ["Base", "Jenkins_Job"],
                "properties": {},
            },
        ],
        [
            {
                "kind": "Jenkins_Runs",
                "start": {"value": "jenkins-1"},
                "end": {"value": "job-1"},
                "properties": {"payload": {"nested": "value"}},
            }
        ],
    )

    importer._import_opengraph_files_directly([("jenkins.json", data, "opengraph")])

    output = capsys.readouterr().out
    assert "[!] OpenGraph jenkins.json: dropped unsupported Neo4j properties:" in output
    for key in ("meta", "mixed", "nullable", "payload"):
        assert key in output


def test_upload_warns_when_mssql_servers_lack_host_edges(capsys):
    conn = RecordingConnection(
        responses=[
            [],
            [{"missing": 1, "examples": ["sql01.example.local"]}],
        ]
    )
    importer = BloodhoundImporter(conn)
    data = _opengraph(
        "MSSQL_Base",
        [
            {
                "id": "sql-1",
                "kinds": ["Base", "MSSQL_Server"],
                "properties": {"name": "sql01.example.local"},
            }
        ],
    )

    importer._upload_json_files([(Path("mssql.json"), "opengraph", data)])

    output = capsys.readouterr().out
    assert "import succeeded, but 1 imported MSSQL_Server node(s)" in output
    assert "Findings that require this relationship for the listed nodes may be missed" in output
    assert "other nodes that satisfy it can still produce findings" in output
    assert "Computer-[:MSSQL_HostFor]->MSSQL_Server" in output
    assert "sql01.example.local" in output
    warning_query, warning_params = conn.queries[-1]
    assert "MSSQL_HostFor" in warning_query
    assert warning_params == {"object_ids": ["sql-1"]}


def test_print_opengraph_requirement_warning_formats_more_suffix_without_used_by(capsys):
    importer = BloodhoundImporter(None)
    warning = OpenGraphRequirementWarning(
        requirement_name="Jenkins job ownership",
        subject_label="Jenkins_Job",
        warning="Collectors should emit Jenkins job ownership.",
        missing_count=5,
        example_names=("job-a", "job-b", "job-c"),
        used_by=(),
    )

    importer._print_opengraph_requirement_warning(warning)

    output = capsys.readouterr().out
    assert "job-a, job-b, job-c, +2 more" in output
    assert "Used by:" not in output


def test_upload_does_not_warn_when_mssql_host_mapping_exists(capsys):
    conn = RecordingConnection(
        responses=[
            [],
            [{"missing": 0, "examples": []}],
        ]
    )
    importer = BloodhoundImporter(conn)
    data = _opengraph(
        "MSSQL_Base",
        [
            {
                "id": "sql-1",
                "kinds": ["Base", "MSSQL_Server"],
                "properties": {"name": "sql01.example.local"},
            }
        ],
    )

    importer._upload_json_files([(Path("mssql.json"), "opengraph", data)])

    output = capsys.readouterr().out
    assert "MSSQL host mapping" not in output


def test_upload_primes_unique_check_owned_opengraph_requirement(
    capsys,
    monkeypatch,
):
    import modules.opengraph_contracts as contracts

    importer_module = importlib.import_module("modules.BloodhoundImporter")
    original_requirements = list(contracts._REGISTERED_CHECK_REQUIREMENTS)
    original_primed = contracts._CHECK_REQUIREMENTS_PRIMED
    requirement = OpenGraphRequirement(
        name="Jenkins job owner mapping",
        when_label="Jenkins_Job",
        required_relationship=RequiredRelationship(
            from_label="Jenkins_User",
            relationship="Jenkins_Owns",
            to_label="Jenkins_Job",
            direction="incoming",
        ),
        warning="Collectors should emit Jenkins job ownership.",
        used_by=("jenkins_job_owner_check",),
    )

    def fake_prime_from_checks():
        contracts.register_opengraph_requirements((requirement,))
        return contracts.registered_opengraph_requirements()

    try:
        contracts._REGISTERED_CHECK_REQUIREMENTS[:] = []
        contracts._CHECK_REQUIREMENTS_PRIMED = False
        monkeypatch.setattr(
            importer_module,
            "prime_from_checks",
            fake_prime_from_checks,
        )
        conn = RecordingConnection(
            responses=[
                [],
                [{"missing": 1, "examples": ["build-release"]}],
            ]
        )
        importer = BloodhoundImporter(conn)
        data = _opengraph(
            "Jenkins_Base",
            [
                {
                    "id": "job-1",
                    "kinds": ["Base", "Jenkins_Job"],
                    "properties": {"name": "build-release"},
                }
            ],
        )

        importer._upload_json_files([(Path("jenkins.json"), "opengraph", data)])

        output = capsys.readouterr().out
        assert "Jenkins job owner mapping" in output
        assert "jenkins_job_owner_check" in output
        assert "Jenkins_Owns" in conn.queries[-1][0]
    finally:
        contracts._REGISTERED_CHECK_REQUIREMENTS[:] = original_requirements
        contracts._CHECK_REQUIREMENTS_PRIMED = original_primed


def test_import_zip_rejects_malformed_opengraph_before_auth_or_writes(
    tmp_path,
    capsys,
):
    conn = RecordingConnection()
    importer = NoSideEffectImporter(conn)
    valid = _opengraph(
        "Jenkins_Base",
        [
            {
                "id": "jenkins-1",
                "kinds": ["Base", "Jenkins_Server"],
                "properties": {},
            }
        ],
    )
    invalid = _opengraph(
        "Jenkins_Base",
        [
            {
                "id": "jenkins-2",
                "kinds": ["Base", "Jenkins_Server"],
                "properties": ["bad"],
            }
        ],
    )
    zip_path = tmp_path / "plugin.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("valid.json", json.dumps(valid))
        archive.writestr("nested/invalid.json", json.dumps(invalid))

    assert importer.import_zip(str(zip_path)) is False

    output = capsys.readouterr().out
    assert "properties must be an object" in output
    assert importer.authenticated is False
    assert conn.queries == []


def test_import_zip_rejects_malformed_nested_json_before_auth_or_writes(
    tmp_path,
    capsys,
):
    conn = RecordingConnection()
    importer = NoSideEffectImporter(conn)
    valid = _opengraph(
        "Jenkins_Base",
        [
            {
                "id": "jenkins-1",
                "kinds": ["Base", "Jenkins_Server"],
                "properties": {},
            }
        ],
    )
    zip_path = tmp_path / "plugin.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("PluginName/data/valid.json", json.dumps(valid))
        archive.writestr("PluginName/data/malformed.json", '{"graph": ')

    assert importer.import_zip(str(zip_path)) is False

    output = capsys.readouterr().out
    assert "malformed.json" in output
    assert "invalid JSON" in output
    assert importer.authenticated is False
    assert conn.queries == []


def test_direct_import_rejects_malformed_metadata_before_any_write():
    conn = RecordingConnection()
    importer = BloodhoundImporter(conn)
    valid = _opengraph(
        "Jenkins_Base",
        [
            {
                "id": "jenkins-1",
                "kinds": ["Base", "Jenkins_Server"],
                "properties": {},
            }
        ],
    )
    invalid = {
        "metadata": [],
        "graph": {
            "nodes": [
                {
                    "id": "jenkins-2",
                    "kinds": ["Base", "Jenkins_Server"],
                    "properties": {},
                }
            ],
            "edges": [],
        },
    }

    with pytest.raises(ValueError, match="metadata must be an object"):
        importer._import_opengraph_files_directly(
            [
                ("valid.json", valid, "opengraph"),
                ("invalid.json", invalid, "opengraph"),
            ]
        )

    assert conn.queries == []


@pytest.mark.parametrize("source_kind", [None, False, 0, []])
def test_opengraph_rejects_present_non_string_source_kind_before_query(source_kind):
    conn = RecordingConnection()
    importer = BloodhoundImporter(conn)
    data = {
        "metadata": {"source_kind": source_kind},
        "graph": {
            "nodes": [
                {
                    "id": "jenkins-1",
                    "kinds": ["Base", "Jenkins_Server"],
                    "properties": {},
                }
            ],
            "edges": [],
        },
    }

    with pytest.raises(ValueError, match="metadata.source_kind must be a string"):
        importer._import_opengraph_files_directly(
            [("jenkins.json", data, "opengraph")]
        )

    assert conn.queries == []


def test_opengraph_treats_empty_source_kind_as_omitted():
    conn = RecordingConnection(responses=[[{"c": 0}]])
    importer = BloodhoundImporter(conn)
    data = {
        "metadata": {"source_kind": ""},
        "graph": {
            "nodes": [
                {
                    "id": "jenkins-1",
                    "kinds": ["Base", "Jenkins_Server"],
                    "properties": {},
                }
            ],
            "edges": [
                {
                    "kind": "Jenkins_AdminTo",
                    "start": {"value": "jenkins-1"},
                    "end": {"value": "external-1"},
                    "properties": {},
                }
            ],
        },
    }

    stub_labels = importer._import_opengraph_files_directly(
        [("jenkins.json", data, "opengraph")]
    )

    assert stub_labels == {"OpenGraph_Stub"}
    assert any(
        "MERGE (n:`OpenGraph_Stub` {objectid: $objectid})" in q
        for q, _ in conn.queries
    )


def test_upload_validates_ad_companion_properties_before_filter():
    class SpyImporter(BloodhoundImporter):
        def __init__(self, neo4j_conn):
            super().__init__(neo4j_conn)
            self.filter_called = False

        def _filter_companion_properties(self, data, manifest):
            self.filter_called = True
            raise AssertionError("filter should not inspect malformed properties")

    conn = RecordingConnection()
    importer = SpyImporter(conn)
    data = _opengraph(
        "Groups",
        [
            {
                "id": "S-1-1",
                "kinds": ["Base", "User"],
                "properties": ["bad"],
            }
        ],
    )

    with pytest.raises(ValueError, match="properties must be an object"):
        importer._upload_json_files([(Path("groups.json"), "ad_companion", data)])

    assert importer.filter_called is False
    assert conn.queries == []


@pytest.mark.parametrize(
    ("filename", "payload", "expected_error"),
    [
        (
            "groups.json",
            {
                "metadata": [],
                "graph": {
                    "nodes": [
                        {
                            "id": "S-1-1",
                            "kinds": ["Base", "User"],
                            "properties": {},
                        }
                    ],
                    "edges": [],
                },
            },
            "metadata must be an object",
        ),
        (
            "groups.json",
            {
                "metadata": {"source_kind": 0},
                "graph": {
                    "nodes": [
                        {
                            "id": "S-1-1",
                            "kinds": ["Base", "User"],
                            "properties": {},
                        }
                    ],
                    "edges": [],
                },
            },
            "metadata.source_kind must be a string",
        ),
        (
            "groups.json",
            {
                "metadata": {"source_kind": "Bad-Kind"},
                "graph": {
                    "nodes": [
                        {
                            "id": "S-1-1",
                            "kinds": ["Base", "User"],
                            "properties": {},
                        }
                    ],
                    "edges": [],
                },
            },
            "metadata.source_kind has unsupported identifier",
        ),
        (
            "seed_data.json",
            {
                "metadata": [],
                "graph": {
                    "nodes": [
                        {
                            "id": "seed",
                            "kinds": ["IgnoreMe"],
                            "properties": {},
                        }
                    ],
                    "edges": [],
                },
            },
            "metadata must be an object",
        ),
        (
            "seed_data.json",
            {
                "metadata": {"source_kind": 0},
                "graph": {
                    "nodes": [
                        {
                            "id": "seed",
                            "kinds": ["IgnoreMe"],
                            "properties": {},
                        }
                    ],
                    "edges": [],
                },
            },
            "metadata.source_kind must be a string",
        ),
        (
            "seed_data.json",
            {
                "metadata": {"source_kind": "Bad-Kind"},
                "graph": {
                    "nodes": [
                        {
                            "id": "seed",
                            "kinds": ["IgnoreMe"],
                            "properties": {},
                        }
                    ],
                    "edges": [],
                },
            },
            "metadata.source_kind has unsupported identifier",
        ),
    ],
)
def test_import_zip_rejects_invalid_metadata_before_dedupe(
    tmp_path,
    capsys,
    filename,
    payload,
    expected_error,
):
    conn = RecordingConnection()
    importer = NoDedupeOrSideEffectImporter(conn)
    zip_path = tmp_path / "plugin.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr(filename, json.dumps(payload))

    assert importer.import_zip(str(zip_path)) is False

    output = capsys.readouterr().out
    assert f"OpenGraph {filename}: {expected_error}" in output
    assert importer.dedupe_called is False
    assert importer.authenticated is False
    assert conn.queries == []


@pytest.mark.parametrize(
    "payload",
    [
        {"metadata": {"source_kind": "Jenkins_Base"}},
        {"$schema": "https://example.test/opengraph.schema.json"},
    ],
)
def test_import_zip_rejects_opengraph_sentinel_missing_graph_before_dedupe(
    tmp_path,
    capsys,
    payload,
):
    conn = RecordingConnection()
    importer = NoDedupeOrSideEffectImporter(conn)
    zip_path = tmp_path / "plugin.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("bad-plugin.json", json.dumps(payload))

    assert importer.import_zip(str(zip_path)) is False

    output = capsys.readouterr().out
    assert "OpenGraph bad-plugin.json: graph must be an object" in output
    assert importer.dedupe_called is False
    assert importer.authenticated is False
    assert conn.queries == []


def test_deduplicate_by_identity_only_applies_to_manifest_identity():
    importer = BloodhoundImporter(None)
    port_path = Path("mssql-port.json")
    host_path = Path("mssql-host.json")
    sccm_path = Path("sccm.json")
    standalone_port = _opengraph(
        "MSSQL_Base",
        [{"id": "sql-port", "kinds": ["Base", "MSSQL_Server"], "properties": {"name": "sql01.example.local:1433"}}],
    )
    standalone_host = _opengraph(
        "MSSQL_Base",
        [{"id": "sql-host", "kinds": ["Base", "MSSQL_Server"], "properties": {"name": "sql01.example.local"}}],
    )
    sccm_with_mssql = _opengraph(
        "SCCM",
        [
            {"id": "sql-sccm", "kinds": ["Base", "MSSQL_Server"], "properties": {"name": "sql01.example.local:1433"}},
            {"id": "site-1", "kinds": ["Base", "SCCM_Site"], "properties": {}},
        ],
    )

    deduped = importer._deduplicate_by_identity(
        [
            (port_path, "opengraph", standalone_port),
            (host_path, "opengraph", standalone_host),
            (sccm_path, "opengraph", sccm_with_mssql),
        ]
    )

    kept_paths = {entry[0] for entry in deduped}
    assert len(deduped) == 3
    assert sccm_path in kept_paths
    assert {port_path, host_path}.issubset(kept_paths)


def test_mssql_identity_includes_port_or_instance_token():
    port_data = _opengraph(
        "MSSQL_Base",
        [
            {
                "id": "sql-port",
                "kinds": ["Base", "MSSQL_Server"],
                "properties": {"name": "sql01.example.local:1444"},
            }
        ],
    )
    instance_data = _opengraph(
        "MSSQL_Base",
        [
            {
                "id": "sql-instance",
                "kinds": ["Base", "MSSQL_Server"],
                "properties": {"name": "sql01.example.local:APP1"},
            }
        ],
    )

    assert _mssql_identity(port_data) == "sql01.example.local|port|1444"
    assert _mssql_identity(instance_data) == "sql01.example.local|instance|app1"


def test_deduplicate_by_identity_retains_distinct_same_host_ports_and_instances():
    importer = BloodhoundImporter(None)
    port_1433_path = Path("sql01-1433.json")
    port_1444_path = Path("sql01-1444.json")
    app1_path = Path("sql01-app1.json")
    app2_path = Path("sql01-app2.json")

    deduped = importer._deduplicate_by_identity(
        [
            (
                port_1433_path,
                "opengraph",
                _opengraph(
                    "MSSQL_Base",
                    [
                        {
                            "id": "sql01-1433",
                            "kinds": ["Base", "MSSQL_Server"],
                            "properties": {"name": "sql01.example.local:1433"},
                        }
                    ],
                ),
            ),
            (
                port_1444_path,
                "opengraph",
                _opengraph(
                    "MSSQL_Base",
                    [
                        {
                            "id": "sql01-1444",
                            "kinds": ["Base", "MSSQL_Server"],
                            "properties": {"name": "sql01.example.local:1444"},
                        }
                    ],
                ),
            ),
            (
                app1_path,
                "opengraph",
                _opengraph(
                    "MSSQL_Base",
                    [
                        {
                            "id": "sql01-app1",
                            "kinds": ["Base", "MSSQL_Server"],
                            "properties": {"name": "sql01.example.local:APP1"},
                        }
                    ],
                ),
            ),
            (
                app2_path,
                "opengraph",
                _opengraph(
                    "MSSQL_Base",
                    [
                        {
                            "id": "sql01-app2",
                            "kinds": ["Base", "MSSQL_Server"],
                            "properties": {"name": "sql01.example.local:APP2"},
                        }
                    ],
                ),
            ),
        ]
    )

    assert {entry[0] for entry in deduped} == {
        port_1433_path,
        port_1444_path,
        app1_path,
        app2_path,
    }


def test_deduplicate_by_identity_suppresses_same_instance_views(capsys):
    importer = BloodhoundImporter(None)
    port_path = Path("sql01-port.json")
    instance_path = Path("sql01-instance.json")

    deduped = importer._deduplicate_by_identity(
        [
            (
                port_path,
                "opengraph",
                _opengraph(
                    "MSSQL_Base",
                    [
                        {
                            "id": "sql01-port",
                            "kinds": ["Base", "MSSQL_Server"],
                            "properties": {
                                "hostname": "sql01.example.local",
                                "instanceName": "APP1",
                                "name": "sql01.example.local:1433",
                            },
                        }
                    ],
                ),
            ),
            (
                instance_path,
                "opengraph",
                _opengraph(
                    "MSSQL_Base",
                    [
                        {
                            "id": "sql01-instance",
                            "kinds": ["Base", "MSSQL_Server"],
                            "properties": {
                                "hostname": "sql01.example.local",
                                "instanceName": "APP1",
                                "name": "sql01.example.local:APP1",
                            },
                        }
                    ],
                ),
            ),
        ]
    )

    assert [entry[0] for entry in deduped] == [instance_path]
    assert "OpenGraph identity dedupe: skipped 1 duplicate" in capsys.readouterr().out


def test_deduplicate_by_identity_matches_normal_mssqlhound_files(capsys):
    importer = BloodhoundImporter(None)
    zip_path = Path("sample_data/MSSQLHound.zip")
    entries = []
    with zipfile.ZipFile(zip_path) as archive:
        for name in (
            "mssql-lab-sql01.training.local.json",
            "mssql-lab-sql01.training.local_SQL01.json",
        ):
            data = json.loads(archive.read(name).decode("utf-8-sig"))
            manifest = importer._select_collector_manifest(data)
            entries.append((Path(name), "opengraph", data))

            assert manifest is not None
            assert manifest.source_kind == "MSSQL_Base"
            assert importer._collector_identity(manifest, data) == (
                "lab-sql01.training.local|instance|sql01"
            )

    deduped = importer._deduplicate_by_identity(entries)

    assert [entry[0].name for entry in deduped] == [
        "mssql-lab-sql01.training.local_SQL01.json"
    ]
    assert "OpenGraph identity dedupe: skipped 1 duplicate" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("properties", "expected", "dropped"),
    [
        (
            {
                "name": "ci.example.local",
                "enabled": True,
                "ports": [80, 443],
                "aliases": ("ci", "jenkins"),
                "empty": [],
            },
            {
                "name": "ci.example.local",
                "enabled": True,
                "ports": [80, 443],
                "aliases": ["ci", "jenkins"],
                "empty": [],
            },
            set(),
        ),
        ({"missing": None}, {}, {"missing"}),
        ({"meta": {"nested": "value"}}, {}, {"meta"}),
        ({"mixed": ["ci", 1]}, {}, {"mixed"}),
        ({4: "bad", "name": "ci"}, {"name": "ci"}, {"4"}),
    ],
)
def test_normalise_neo4j_properties_filters_unsupported_values(properties, expected, dropped):
    dropped_keys = set()

    normalised = _normalise_neo4j_properties(properties, dropped_keys)

    assert normalised == expected
    assert dropped_keys == dropped


@pytest.mark.parametrize(
    "identifier",
    ["Base", "MSSQL_Server", "SCCM_Site", "OpenGraph_Stub", "_Custom123"],
)
def test_safe_cypher_identifier_accepts_supported_labels(identifier):
    assert safe_cypher_identifier(identifier, "test") == identifier


@pytest.mark.parametrize(
    "identifier",
    ["", "1Base", "MSSQL-Server", "SCCM Site", "User`) DETACH DELETE n //"],
)
def test_safe_cypher_identifier_rejects_unsafe_labels(identifier):
    with pytest.raises(ValueError):
        safe_cypher_identifier(identifier, "test")


def test_importer_uses_configured_ingestion_timeout():
    importer = BloodhoundImporter(None, ingestion_timeout_seconds=42)

    assert importer.ingestion_timeout_seconds == 42


def test_importer_reads_ingestion_timeout_from_environment(monkeypatch):
    monkeypatch.setenv("ADPF_BH_INGESTION_TIMEOUT_SECONDS", "900")

    importer = BloodhoundImporter(None)

    assert importer.ingestion_timeout_seconds == 900


def test_importer_rejects_invalid_ingestion_timeout(monkeypatch):
    monkeypatch.setenv("ADPF_BH_INGESTION_TIMEOUT_SECONDS", "never")

    with pytest.raises(ValueError, match="positive integer"):
        BloodhoundImporter(None)


@pytest.mark.parametrize("label", ["Base", "User", "Computer", "Group"])
def test_merge_orphan_stubs_refuses_broad_labels_before_query(label):
    conn = RecordingConnection()
    importer = BloodhoundImporter(conn)

    with pytest.raises(ValueError):
        importer._merge_orphan_stubs(label)

    assert conn.queries == []
