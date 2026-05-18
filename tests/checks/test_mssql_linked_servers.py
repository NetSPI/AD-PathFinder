import pytest

from checks.mssql_linked_servers import MSSQLLinkedServersCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_linked_server_with_sysadmin(clean_neo4j):
    load_fixture(clean_neo4j, "mssql_linked_servers.cypher")
    findings = run_check(MSSQLLinkedServersCheck, clean_neo4j, domain_filter="TEST.LOCAL")
    assert MSSQLLinkedServersCheck.RISK_LEVEL == "Medium"
    assert len(findings) == 1
    assert "S-1-5-21-TEST-2101" in findings
    assert isinstance(findings["S-1-5-21-TEST-2101"], str)
    assert "sysadmin" in findings["S-1-5-21-TEST-2101"]
