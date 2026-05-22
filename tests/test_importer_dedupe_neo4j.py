import pytest

from modules.BloodhoundImporter import BloodhoundImporter
from tests.check_harness import load_fixture

pytestmark = pytest.mark.neo4j


def test_dedupe_collapses_duplicate_mssql_server_names(clean_neo4j):
    load_fixture(clean_neo4j, "dedupe_mssql_servers.cypher")

    importer = BloodhoundImporter(None)
    importer.connection = clean_neo4j

    importer._dedupe_mssql_servers()

    sccmdb_nodes = clean_neo4j.query(
        "MATCH (s:MSSQL_Server) WHERE toLower(s.name) = 'sccmdb.training.local:1433' "
        "RETURN s.objectid AS oid ORDER BY oid"
    )
    assert [r['oid'] for r in sccmdb_nodes] == ['sccmdb:1433']

    sql01_nodes = clean_neo4j.query(
        "MATCH (s:MSSQL_Server) WHERE toLower(s.name) STARTS WITH 'sql01.training.local' "
        "RETURN s.objectid AS oid ORDER BY s.name"
    )
    assert [r['oid'] for r in sql01_nodes] == [
        'sql01\\sql01:1433',
        'sql01\\app1:1444',
        'sql01\\app2:1455',
    ]


def test_dedupe_preserves_stale_only_properties_on_canonical(clean_neo4j):
    load_fixture(clean_neo4j, "dedupe_mssql_servers.cypher")
    importer = BloodhoundImporter(None)
    importer.connection = clean_neo4j

    importer._dedupe_mssql_servers()

    rows = clean_neo4j.query(
        "MATCH (s:MSSQL_Server {objectid: 'sccmdb:1433'}) "
        "RETURN s.version AS version, s.xpCmdShellEnabled AS xp, "
        "s.extendedProtection AS epa, s.sqlServerName AS svc"
    )
    assert rows[0]['version'] == '15.0.4322.2'
    assert rows[0]['xp'] is False
    assert rows[0]['epa'] == 'Off'
    assert rows[0]['svc'] == 'SCCMDB'


def test_dedupe_reroutes_relationships_from_stale_to_canonical(clean_neo4j):
    load_fixture(clean_neo4j, "dedupe_mssql_servers.cypher")
    importer = BloodhoundImporter(None)
    importer.connection = clean_neo4j

    importer._dedupe_mssql_servers()

    rows = clean_neo4j.query(
        "MATCH (canonical:MSSQL_Server {objectid: 'sccmdb:1433'})-[:MSSQL_Contains]->(role:MSSQL_ServerRole {name: 'sysadmin'}) "
        "RETURN count(role) AS c"
    )
    assert rows[0]['c'] == 1


def test_dedupe_preserves_existing_canonical_relationship_properties(clean_neo4j):
    clean_neo4j.query("""
        CREATE (canonical:MSSQL_Server:MSSQL_Base:Base {
          objectid: 'canonical:1433',
          name: 'sql.training.local:1433',
          sqlServerName: 'SQL',
          version: '15.0'
        })
        CREATE (stale:MSSQL_Server:MSSQL_Base:Base {
          objectid: 'stale:1433',
          name: 'SQL.TRAINING.LOCAL:1433'
        })
        CREATE (role:MSSQL_ServerRole:MSSQL_Base:Base {
          objectid: 'sysadmin@sql',
          name: 'sysadmin'
        })
        CREATE (canonical)-[:MSSQL_Contains {
          canonicalOnly: 'yes',
          shared: 'canonical'
        }]->(role)
        CREATE (stale)-[:MSSQL_Contains {
          staleOnly: 'yes',
          shared: 'stale'
        }]->(role)
    """)
    importer = BloodhoundImporter(None)
    importer.connection = clean_neo4j

    importer._dedupe_mssql_servers()

    rows = clean_neo4j.query(
        "MATCH (:MSSQL_Server {objectid: 'canonical:1433'})-[r:MSSQL_Contains]->(:MSSQL_ServerRole {name: 'sysadmin'}) "
        "RETURN count(r) AS c, r.canonicalOnly AS canonicalOnly, r.staleOnly AS staleOnly, r.shared AS shared"
    )
    assert rows[0]['c'] == 1
    assert rows[0]['canonicalOnly'] == 'yes'
    assert rows[0]['staleOnly'] == 'yes'
    assert rows[0]['shared'] == 'canonical'


def test_dedupe_does_not_rewrite_stale_canonical_edges_as_self_loops(clean_neo4j):
    clean_neo4j.query("""
        CREATE (canonical:MSSQL_Server:MSSQL_Base:Base {
          objectid: 'canonical:1433',
          name: 'sql.training.local:1433',
          sqlServerName: 'SQL',
          version: '15.0'
        })
        CREATE (stale:MSSQL_Server:MSSQL_Base:Base {
          objectid: 'stale:1433',
          name: 'SQL.TRAINING.LOCAL:1433'
        })
        CREATE (canonical)-[:MSSQL_LinkedAsAdmin]->(stale)
        CREATE (stale)-[:MSSQL_LinkedAsAdmin]->(canonical)
    """)
    importer = BloodhoundImporter(None)
    importer.connection = clean_neo4j

    importer._dedupe_mssql_servers()

    rows = clean_neo4j.query(
        "MATCH (canonical:MSSQL_Server {objectid: 'canonical:1433'})-[r]->(canonical) "
        "RETURN count(r) AS c"
    )
    assert rows[0]['c'] == 0
