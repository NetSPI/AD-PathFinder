import pytest

from checks.mssql_sccm import MSSQLSCCMCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_cross_schema_path_to_sccm_site(clean_neo4j):
    load_fixture(clean_neo4j, "mssql_sccm.cypher")

    sccm_rows = clean_neo4j.query(
        "MATCH (n:SCCM_Site) WHERE toUpper(n.sourceForest) = 'TEST.LOCAL' RETURN count(n) AS c"
    )
    assert sccm_rows and sccm_rows[0]['c'] > 0
    mssql_rows = clean_neo4j.query(
        "MATCH (n:MSSQL_Server) WHERE toUpper(n.name) CONTAINS '.TEST.LOCAL:' RETURN count(n) AS c"
    )
    assert mssql_rows and mssql_rows[0]['c'] > 0

    findings = run_check(MSSQLSCCMCheck, clean_neo4j, domain_filter="TEST.LOCAL")
    assert MSSQLSCCMCheck.RISK_LEVEL == "Critical"
    assert len(findings) >= 1
    assert "S-1-5-21-TEST-1300" in findings
    assert isinstance(findings["S-1-5-21-TEST-1300"], str)
    assert "Base" not in findings["S-1-5-21-TEST-1300"]
    assert "SCCM_Site" in findings["S-1-5-21-TEST-1300"]
