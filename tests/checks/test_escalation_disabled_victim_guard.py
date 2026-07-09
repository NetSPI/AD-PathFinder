import pytest

from modules.neo4j_data import Neo4jData
from tests.check_harness import load_fixture

pytestmark = pytest.mark.neo4j


def _has_path(results, sid):
    return any(r.get("hasEscalationPath") for r in results.get(sid, []))


def _edges(results, sid):
    for r in results.get(sid, []):
        return [item for item in (r.get("fullPath") or []) if isinstance(item, str)]
    return []


def test_disabled_victim_pruned_unless_entered_by_write_edge(clean_neo4j):
    load_fixture(clean_neo4j, "escalation_disabled_victim_guard.cypher")
    data = Neo4jData(clean_neo4j, excluded_relationships=[])

    nonwrite_disabled = "S-1-5-21-TEST-90011"
    write_disabled = "S-1-5-21-TEST-90012"
    nonwrite_enabled = "S-1-5-21-TEST-90013"
    both_disabled = "S-1-5-21-TEST-90014"
    writeacctres_disabled = "S-1-5-21-TEST-90015"

    results = data._find_escalation_paths_v2(
        [nonwrite_disabled, write_disabled, nonwrite_enabled, both_disabled,
         writeacctres_disabled],
        raise_on_error=True,
    )

    assert _has_path(results, nonwrite_disabled) is False
    assert _has_path(results, write_disabled) is True
    assert _has_path(results, nonwrite_enabled) is True
    assert _has_path(results, both_disabled) is True
    assert "GenericWrite" in _edges(results, both_disabled)
    assert "AllExtendedRights" not in _edges(results, both_disabled)
    assert _has_path(results, writeacctres_disabled) is True
