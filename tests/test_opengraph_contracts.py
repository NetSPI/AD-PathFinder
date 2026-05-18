import json
import subprocess
import sys

import pytest

from modules.opengraph_contracts import (
    OpenGraphRequirement,
    RequiredRelationship,
    evaluate_opengraph_requirements,
    mssql_host_mapping_requirement,
    prime_from_checks,
    register_opengraph_requirements,
)


class RecordingConnection:
    def __init__(self, responses=None):
        self.queries = []
        self.responses = list(responses or [])

    def query(self, query, parameters=None):
        self.queries.append((query, parameters))
        if self.responses:
            return self.responses.pop(0)
        return []


def _opengraph(source_kind, nodes, edges=None):
    return {
        "metadata": {"source_kind": source_kind},
        "graph": {"nodes": nodes, "edges": edges or []},
    }


def test_evaluator_warns_for_mssql_servers_lacking_host_mapping():
    conn = RecordingConnection(
        responses=[
            [{"missing": 4, "examples": ["sql01", "sql02", "sql03"]}],
        ]
    )
    data = _opengraph(
        "MSSQL_Base",
        [
            {
                "id": "sql-1",
                "kinds": ["Base", "MSSQL_Server"],
                "properties": {"name": "sql01"},
            }
        ],
    )

    warnings = evaluate_opengraph_requirements(
        conn,
        [("mssql.json", data, "opengraph")],
    )

    assert len(warnings) == 1
    warning = warnings[0]
    assert warning.requirement_name == "MSSQL host mapping"
    assert warning.subject_label == "MSSQL_Server"
    assert warning.missing_count == 4
    assert warning.example_names == ("sql01", "sql02", "sql03")
    assert "mssql_linked_servers" in warning.used_by
    query, parameters = conn.queries[0]
    assert "MATCH (source:`Computer`)-[:`MSSQL_HostFor`]->(subject)" in query
    assert parameters == {"object_ids": ["sql-1"]}


def test_evaluator_ignores_ad_companion_payload_edge_endpoints_as_anchors():
    conn = RecordingConnection()
    data = _opengraph(
        "Groups",
        [
            {
                "id": "sql-1",
                "kinds": ["Base", "MSSQL_Server"],
                "properties": {"name": "sql01"},
            },
            {
                "id": "S-1-5-21-1",
                "kinds": ["Base", "Computer"],
                "properties": {"name": "sql01.example.local"},
            }
        ],
        [
            {
                "kind": "MSSQL_HostFor",
                "start": {"value": "S-1-5-21-1"},
                "end": {"value": "sql-1"},
                "properties": {},
            }
        ],
    )

    warnings = evaluate_opengraph_requirements(
        conn,
        [("groups.json", data, "ad_companion")],
    )

    assert warnings == []
    assert conn.queries == []


def test_evaluator_returns_no_warning_when_relationship_requirement_is_satisfied():
    conn = RecordingConnection(
        responses=[
            [{"missing": 0, "examples": []}],
        ]
    )
    data = _opengraph(
        "MSSQL_Base",
        [
            {
                "id": "sql-1",
                "kinds": ["Base", "MSSQL_Server"],
                "properties": {"name": "sql01"},
            }
        ],
    )

    warnings = evaluate_opengraph_requirements(
        conn,
        [("mssql.json", data, "opengraph")],
    )

    assert warnings == []


def test_evaluator_checks_outgoing_relationship_requirements():
    conn = RecordingConnection(
        responses=[
            [{"missing": 2, "examples": ["job-a", "job-b"]}],
        ]
    )
    data = _opengraph(
        "Jenkins_Base",
        [
            {
                "id": "job-1",
                "kinds": ["Base", "Jenkins_Job"],
                "properties": {"name": "job-a"},
            }
        ],
    )
    requirement = OpenGraphRequirement(
        name="Jenkins job agent mapping",
        when_label="Jenkins_Job",
        required_relationship=RequiredRelationship(
            from_label="Jenkins_Job",
            relationship="Jenkins_RunsOn",
            to_label="Jenkins_Agent",
            direction="outgoing",
        ),
        warning="Collectors should emit Jenkins job agent mapping.",
    )

    warnings = evaluate_opengraph_requirements(
        conn,
        [("jenkins.json", data, "opengraph")],
        requirements=[requirement],
    )

    assert len(warnings) == 1
    query, parameters = conn.queries[0]
    assert "MATCH (subject)-[:`Jenkins_RunsOn`]->(target:`Jenkins_Agent`)" in query
    assert parameters == {"object_ids": ["job-1"]}


def test_evaluator_merges_equivalent_registered_requirements():
    import modules.opengraph_contracts as contracts

    original_requirements = list(contracts._REGISTERED_CHECK_REQUIREMENTS)
    original_primed = contracts._CHECK_REQUIREMENTS_PRIMED
    try:
        contracts._REGISTERED_CHECK_REQUIREMENTS[:] = []
        contracts._CHECK_REQUIREMENTS_PRIMED = True
        register_opengraph_requirements(
            [
                mssql_host_mapping_requirement("custom_check"),
            ]
        )

        conn = RecordingConnection(
            responses=[
                [{"missing": 1, "examples": ["sql01"]}],
            ]
        )
        data = _opengraph(
            "MSSQL_Base",
            [
                {
                    "id": "sql-1",
                    "kinds": ["Base", "MSSQL_Server"],
                    "properties": {"name": "sql01"},
                }
            ],
        )

        warnings = evaluate_opengraph_requirements(
            conn,
            [("mssql.json", data, "opengraph")],
        )

        assert len(warnings) == 1
        assert "custom_check" in warnings[0].used_by
        assert "mssql_linked_servers" in warnings[0].used_by
    finally:
        contracts._REGISTERED_CHECK_REQUIREMENTS[:] = original_requirements
        contracts._CHECK_REQUIREMENTS_PRIMED = original_primed


def test_prime_from_checks_loads_requirements_from_importer_entrypoint():
    code = """
import json
from importlib import import_module
from modules import opengraph_contracts as contracts

import_module("modules.BloodhoundImporter")
contracts.prime_from_checks()
used_by = sorted({
    check
    for requirement in contracts.registered_opengraph_requirements()
    for check in requirement.used_by
})
print(json.dumps(used_by))
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        check=True,
        capture_output=True,
        text=True,
    )

    used_by = set(json.loads(result.stdout))
    assert {
        "mssql_linked_servers",
        "mssql_impersonation",
        "mssql_ntlm_relay",
        "sccm_takeover1",
        "sccm_takeover2",
    }.issubset(used_by)


def test_prime_from_checks_fails_fast_on_malformed_check_metadata(monkeypatch):
    import modules.opengraph_contracts as contracts
    from checks.core.registry import CheckRegistry

    class BrokenCheck:
        OPENGRAPH_REQUIREMENTS = ("not-a-requirement",)

    original_requirements = list(contracts._REGISTERED_CHECK_REQUIREMENTS)
    original_primed = contracts._CHECK_REQUIREMENTS_PRIMED
    try:
        contracts._REGISTERED_CHECK_REQUIREMENTS[:] = []
        contracts._CHECK_REQUIREMENTS_PRIMED = False
        monkeypatch.setattr(
            CheckRegistry,
            "get_all_checks",
            classmethod(lambda cls: [BrokenCheck]),
        )

        with pytest.raises(TypeError, match="OpenGraph check requirements"):
            prime_from_checks()

        assert contracts._CHECK_REQUIREMENTS_PRIMED is False
    finally:
        contracts._REGISTERED_CHECK_REQUIREMENTS[:] = original_requirements
        contracts._CHECK_REQUIREMENTS_PRIMED = original_primed


def test_evaluator_rejects_invalid_requirement_identifiers_before_query():
    conn = RecordingConnection()

    with pytest.raises(ValueError):
        OpenGraphRequirement(
            name="bad",
            when_label="Bad-Label",
            required_relationship=RequiredRelationship(
                from_label="Computer",
                relationship="MSSQL_HostFor",
                to_label="Bad-Label",
            ),
            warning="bad",
        )

    assert conn.queries == []


def test_requirement_rejects_mismatched_incoming_subject_at_construction():
    with pytest.raises(ValueError, match="target the when_label"):
        OpenGraphRequirement(
            name="bad",
            when_label="MSSQL_Server",
            required_relationship=RequiredRelationship(
                from_label="Computer",
                relationship="MSSQL_HostFor",
                to_label="Jenkins_Server",
            ),
            warning="bad",
        )
