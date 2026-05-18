from modules.neo4j_data import Neo4jData
from checks.core.dependencies import CheckDependencies
from checks.mssql_privilege_escalation import MSSQLPrivilegeEscalationCheck
from checks.mssql_sccm import MSSQLSCCMCheck


class RecordingQueryConnection:
    def __init__(self):
        self.queries = []

    def query(self, query, parameters=None, name=None):
        self.queries.append((query, parameters, name))
        return []


class MinimalNeo4jData:
    def __init__(self, conn):
        self.conn = conn
        self._domain_filter = None


def _build_check(check_class):
    conn = RecordingQueryConnection()
    neo4j_data = MinimalNeo4jData(conn)
    return check_class(CheckDependencies(neo4j_data)), conn


class SidLookupConnection:
    def __init__(self):
        self.queries = []

    def query(self, query, parameters=None, name=None):
        self.queries.append((query, parameters, name))
        return [
            {
                "name": "sql01.example.local",
                "samaccountname": None,
                "sid": "S-1-5-21-example-1105",
                "dn": None,
                "displayname": None,
                "all_types": ["Base", "MSSQL_Server"],
            }
        ]


def test_sid_object_lookup_suppresses_plugin_only_type_in_ad_report_context():
    conn = SidLookupConnection()
    neo4j_data = Neo4jData(conn)

    result = neo4j_data.get_object_details_by_sids(["S-1-5-21-example-1105"])

    assert result[0]["type"] == "Unknown"
    query, parameters, name = conn.queries[0]
    assert name == "get_object_details_by_sids"
    assert "ORDER BY objectSid, label_rank" in query
    assert "ad_labels" in parameters
    assert "metadata_labels" in parameters


def test_mssql_sccm_check_canonicalises_broad_platform_labels():
    check, conn = _build_check(MSSQLSCCMCheck)

    check._fetch_priv_esc_paths()
    check._fetch_coercion_paths()
    check._fetch_service_account_paths()

    queries = "\n".join(query for query, _parameters, _name in conn.queries)
    assert "WHEN target:MSSQL_Base THEN 'MSSQL'" in queries
    assert "WHEN target:SCCM_Base THEN 'SCCM'" in queries
    assert "WHEN source:MSSQL_Base THEN 'MSSQL'" in queries
    assert "WHEN source:SCCM_Base THEN 'SCCM'" in queries
    assert "WHEN serviceAccount:MSSQL_Base THEN 'MSSQL'" in queries
    assert "WHEN serviceAccount:SCCM_Base THEN 'SCCM'" in queries


def test_mssql_privilege_check_canonicalises_broad_platform_labels():
    check, conn = _build_check(MSSQLPrivilegeEscalationCheck)

    check._fetch_escalation_paths()

    query = conn.queries[0][0]
    assert "WHEN target:MSSQL_Base THEN 'MSSQL'" in query
    assert "WHEN target:SCCM_Base THEN 'SCCM'" in query
