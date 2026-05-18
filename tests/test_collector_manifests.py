import json
import subprocess
import sys
from pathlib import Path

import pytest

from modules.BloodhoundImporter import BloodhoundImporter
from modules.opengraph_collectors import (
    CollectorManifest,
    register_collector_manifest,
    registered_manifests,
)


def test_collector_manifest_validates_source_kind_and_labels():
    with pytest.raises(ValueError, match="source_kind"):
        CollectorManifest(source_kind="", principal_kinds=("Fake_Node",))

    with pytest.raises(ValueError, match="Unsupported node label"):
        CollectorManifest(source_kind="Fake", principal_kinds=("Fake-Node",))

    with pytest.raises(ValueError, match="Unsupported node label"):
        CollectorManifest(
            source_kind="Fake",
            principal_kinds=("Fake_Node",),
            owned_kinds=("Fake_Node", "Fake-Child"),
        )

    with pytest.raises(ValueError, match="principal_kinds must not be empty"):
        CollectorManifest(source_kind="Fake", principal_kinds=())

    with pytest.raises(ValueError, match="owned_kinds must include principal_kinds"):
        CollectorManifest(
            source_kind="Fake",
            principal_kinds=("Fake_Server",),
            owned_kinds=("Fake_Login",),
        )


def test_collector_manifest_validates_identity_modes():
    with pytest.raises(ValueError, match="mutually exclusive"):
        CollectorManifest(
            source_kind="Fake",
            principal_kinds=("Fake_Node",),
            identity_properties=("name",),
            identity_fn=lambda _: "fake",
        )

    with pytest.raises(TypeError, match="identity_fn must be callable"):
        CollectorManifest(
            source_kind="Fake",
            principal_kinds=("Fake_Node",),
            identity_fn="not-callable",
        )


def test_register_collector_manifest_records_manifest():
    import modules.opengraph_collectors as collectors

    original_manifests = list(collectors._REGISTERED_COLLECTOR_MANIFESTS)
    original_primed = collectors._COLLECTORS_PRIMED
    try:
        collectors._REGISTERED_COLLECTOR_MANIFESTS[:] = []
        collectors._COLLECTORS_PRIMED = False
        manifest = CollectorManifest(
            source_kind="Fake",
            principal_kinds=("Fake_Node",),
            identity_properties=("name",),
        )

        register_collector_manifest(manifest)

        assert registered_manifests() == (manifest,)
    finally:
        collectors._REGISTERED_COLLECTOR_MANIFESTS[:] = original_manifests
        collectors._COLLECTORS_PRIMED = original_primed


def test_fakehound_manifest_drives_importer_without_importer_branch(tmp_path):
    import modules.opengraph_collectors as collectors
    from modules.opengraph_identifiers import reserved_labels

    original_manifests = list(collectors._REGISTERED_COLLECTOR_MANIFESTS)
    original_primed = collectors._COLLECTORS_PRIMED
    try:
        collectors._REGISTERED_COLLECTOR_MANIFESTS[:] = []
        collectors._COLLECTORS_PRIMED = True
        fake_plugin = CollectorManifest(
            source_kind="Fake_Base",
            principal_kinds=("Fake_Server",),
            identity_properties=("name",),
        )
        fake_companion = CollectorManifest(
            source_kind="FakeCompanion",
            principal_kinds=("Fake_User",),
            reserved_labels=("Fake_User",),
            merge_strategy="companion_additive",
            allowed_companion_properties=("FakeAllowed",),
            companion_property_prefixes=("FakePrefix",),
        )
        register_collector_manifest(fake_plugin)
        register_collector_manifest(fake_companion)

        importer = BloodhoundImporter(None)
        fake_data = {
            "metadata": {"source_kind": "Fake_Base"},
            "graph": {
                "nodes": [
                    {
                        "id": "fake-server-1",
                        "kinds": ["Base", "Fake_Server"],
                        "properties": {"name": "fake01.example.local"},
                    }
                ],
                "edges": [],
            },
        }
        fake_path = tmp_path / "fake.json"
        fake_path.write_text(json.dumps(fake_data), encoding="utf-8")

        companion_data = {
            "metadata": {"source_kind": "FakeCompanion"},
            "graph": {
                "nodes": [
                    {
                        "id": "S-1-5-21-fake-1101",
                        "kinds": ["Base", "Fake_User"],
                        "properties": {
                            "name": "ALICE@EXAMPLE.LOCAL",
                            "FakeAllowed": True,
                            "FakePrefixLevel": "high",
                            "Ignored": "drop",
                        },
                    }
                ],
                "edges": [],
            },
        }
        companion_path = tmp_path / "fake-companion.json"
        companion_path.write_text(json.dumps(companion_data), encoding="utf-8")

        assert importer._classify_json_file(fake_path)[0] == "opengraph"
        assert importer._classify_json_file(companion_path)[0] == "ad_companion"
        assert "Fake_User" in reserved_labels()

        filtered = importer._filter_companion_properties(
            companion_data,
            fake_companion,
        )
        assert filtered["graph"]["nodes"][0]["properties"] == {
            "FakeAllowed": True,
            "FakePrefixLevel": "high",
        }

        replacement = {
            **fake_data,
            "graph": {
                "nodes": [
                    {
                        "id": "fake-server-2",
                        "kinds": ["Base", "Fake_Server"],
                        "properties": {"name": "fake01.example.local"},
                    }
                ],
                "edges": [],
            },
        }
        deduped = importer._deduplicate_by_identity(
            [
                (Path("fake-old.json"), "opengraph", fake_data),
                (Path("fake-new.json"), "opengraph", replacement),
            ]
        )

        assert [entry[0].name for entry in deduped] == ["fake-new.json"]
        assert "FakeHound" not in Path("modules/BloodhoundImporter.py").read_text(
            encoding="utf-8"
        )
    finally:
        collectors._REGISTERED_COLLECTOR_MANIFESTS[:] = original_manifests
        collectors._COLLECTORS_PRIMED = original_primed


def test_prime_from_collectors_registers_builtins_once():
    code = """
import json
from modules.opengraph_collectors import prime_from_collectors, registered_manifests

first = prime_from_collectors()
second = prime_from_collectors()
print(json.dumps({
    "first": [manifest.source_kind for manifest in first],
    "second": [manifest.source_kind for manifest in second],
}))
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["first"] == payload["second"]
    assert payload["first"].count("SharpHound") == 1
    assert payload["first"].count("MSSQL_Base") == 1


def test_collector_package_is_in_distribution_package_list():
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")

    assert '"modules.collectors"' in pyproject


def test_builtin_sharphound_manifest_matches_companion_policy():
    import modules.opengraph_collectors as collectors

    original_manifests = list(collectors._REGISTERED_COLLECTOR_MANIFESTS)
    original_primed = collectors._COLLECTORS_PRIMED
    try:
        collectors._REGISTERED_COLLECTOR_MANIFESTS[:] = []
        collectors._COLLECTORS_PRIMED = False
        for module_name in (
            "modules.collectors",
            "modules.collectors.mssqlhound",
            "modules.collectors.sharphound",
        ):
            sys.modules.pop(module_name, None)

        manifests = collectors.prime_from_collectors()
        sharphound = next(
            manifest for manifest in manifests if manifest.source_kind == "SharpHound"
        )

        assert sharphound.merge_strategy == "companion_additive"
        assert sharphound.principal_kinds == ("User", "Computer", "Group")
        assert sharphound.owned_kinds == ("User", "Computer", "Group")
        assert "SMBSigningRequired" in sharphound.allowed_companion_properties
        assert sharphound.companion_property_prefixes == ("SCCM",)
    finally:
        collectors._REGISTERED_COLLECTOR_MANIFESTS[:] = original_manifests
        collectors._COLLECTORS_PRIMED = original_primed


def test_builtin_mssql_identity_matches_current_parser_behavior():
    import modules.opengraph_collectors as collectors

    original_manifests = list(collectors._REGISTERED_COLLECTOR_MANIFESTS)
    try:
        from modules.collectors.mssqlhound import _mssql_identity

        port_payload = {
            "graph": {
                "nodes": [
                    {
                        "id": "sql-port",
                        "kinds": ["Base", "MSSQL_Server"],
                        "properties": {"name": "sql01.example.local:1444"},
                    }
                ],
                "edges": [],
            }
        }
        instance_payload = {
            "graph": {
                "nodes": [
                    {
                        "id": "sql-instance",
                        "kinds": ["Base", "MSSQL_Server"],
                        "properties": {
                            "hostname": "sql01.example.local",
                            "instanceName": "APP1",
                            "name": "sql01.example.local:1433",
                        },
                    }
                ],
                "edges": [],
            }
        }

        assert _mssql_identity(port_payload) == "sql01.example.local|port|1444"
        assert _mssql_identity(instance_payload) == (
            "sql01.example.local|instance|app1"
        )
    finally:
        collectors._REGISTERED_COLLECTOR_MANIFESTS[:] = original_manifests


def test_builtin_mssql_manifest_allows_normal_mssqlhound_node_kinds():
    from modules.collectors.mssqlhound import MSSQLHOUND_MANIFEST

    assert MSSQLHOUND_MANIFEST.principal_kinds == ("MSSQL_Server",)
    assert set(MSSQLHOUND_MANIFEST.owned_kinds) == {
        "MSSQL_Database",
        "MSSQL_DatabaseRole",
        "MSSQL_DatabaseUser",
        "MSSQL_Login",
        "MSSQL_Server",
        "MSSQL_ServerRole",
    }
