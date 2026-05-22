import pytest

from modules.BloodhoundImporter import BloodhoundImporter
from tests.check_harness import load_fixture

pytestmark = pytest.mark.neo4j


def _linked_edge_count(conn):
    rows = conn.query(
        "MATCH ()-[r:MSSQL_LinkedAsAdmin|MSSQL_LinkedTo]->() RETURN count(r) AS c"
    )
    return rows[0]["c"]


def test_canonicalizer_creates_source_to_target_edges(clean_neo4j):
    load_fixture(clean_neo4j, "canonicalize_linked_server.cypher")
    importer = BloodhoundImporter(None)
    importer.connection = clean_neo4j

    merged = importer._canonicalize_mssql_linked_server_edges()

    assert merged == 2
    admin = clean_neo4j.query(
        "MATCH (s:MSSQL_Server {objectid: 'S-1-5-21-TEST-CANON-A:1433'})"
        "-[:MSSQL_LinkedAsAdmin]->(t:MSSQL_Server {objectid: 'S-1-5-21-TEST-TGT-A:1433'}) "
        "RETURN count(*) AS c"
    )
    linked_to = clean_neo4j.query(
        "MATCH (s:MSSQL_Server {objectid: 'S-1-5-21-TEST-CANON-B:1433'})"
        "-[:MSSQL_LinkedTo]->(t:MSSQL_Server {objectid: 'S-1-5-21-TEST-TGT-B:1433'}) "
        "RETURN count(*) AS c"
    )
    assert admin[0]["c"] == 1
    assert linked_to[0]["c"] == 1


def test_canonicalizer_is_idempotent_on_reimport(clean_neo4j):
    load_fixture(clean_neo4j, "canonicalize_linked_server.cypher")
    importer = BloodhoundImporter(None)
    importer.connection = clean_neo4j

    first = importer._canonicalize_mssql_linked_server_edges()
    edges_after_first = _linked_edge_count(clean_neo4j)

    second = importer._canonicalize_mssql_linked_server_edges()
    edges_after_second = _linked_edge_count(clean_neo4j)

    # MERGE reports ensured edges on re-import without creating duplicates.
    assert first == 2
    assert second == 2
    assert edges_after_first == 4
    assert edges_after_second == 4
