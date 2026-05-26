import os
import sys
from pathlib import Path
from urllib.parse import urlparse

# Bootstrap sys.path so test files can import `modules.*` / `checks.*` without
# per-file hacks. Must run before pytest collects any test module.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from modules.neo4j_connection import Neo4jConnection


DEFAULT_NEO4J_TEST_URI = "bolt://localhost:17687"
DEFAULT_NEO4J_TEST_PASSWORD = "testpassword"


def _delete_in_batches(conn, cypher, batch_size=500):
    while True:
        rows = conn.query(cypher, parameters={"batch_size": batch_size})
        deleted = rows[0].get("deleted", 0) if rows else 0
        if not deleted:
            break


def _wipe_neo4j(conn):
    _delete_in_batches(
        conn,
        "MATCH ()-[r]->() WITH r LIMIT $batch_size DELETE r RETURN count(*) AS deleted",
    )
    _delete_in_batches(
        conn,
        "MATCH (n) WITH n LIMIT $batch_size DELETE n RETURN count(*) AS deleted",
    )


def _bloodhound_default_port(uri):
    try:
        parsed = urlparse(uri)
    except Exception:
        return False
    host = (parsed.hostname or "").lower()
    return host in {"localhost", "127.0.0.1", "::1", "0.0.0.0"} and (parsed.port or 7687) == 7687


@pytest.fixture(scope="session")
def neo4j_conn():
    if os.environ.get("ADPF_TEST_ALLOW_WIPE") != "1":
        pytest.fail(
            "Refusing to run Neo4j fixture tests: ADPF_TEST_ALLOW_WIPE=1 is not set. "
            "This harness wipes the target database before and after each test. "
            "Set the env var only when NEO4J_URI points at a disposable test instance."
        )

    uri = os.environ.get("NEO4J_URI", DEFAULT_NEO4J_TEST_URI)

    if _bloodhound_default_port(uri):
        in_ci = os.environ.get("GITHUB_ACTIONS") == "true"
        force = os.environ.get("ADPF_TEST_FORCE_DEFAULT_PORT") == "1"
        if not (in_ci or force):
            pytest.fail(
                f"Refusing to wipe {uri}: that is the BloodHound default port and "
                "almost certainly a real instance. Point NEO4J_URI at the disposable "
                "container on port 17687, or set ADPF_TEST_FORCE_DEFAULT_PORT=1 to override."
            )

    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD", DEFAULT_NEO4J_TEST_PASSWORD)
    conn = Neo4jConnection(uri, user, password)
    assert conn.is_connected(), f"Neo4j not reachable at {uri}"
    yield conn
    conn.close()


@pytest.fixture
def clean_neo4j(neo4j_conn):
    _wipe_neo4j(neo4j_conn)
    yield neo4j_conn
    _wipe_neo4j(neo4j_conn)
