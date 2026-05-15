import pytest

from checks.mssql_ntlm_relay import MSSQLNTLMRelayCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_server_with_service_account_and_relay_target(clean_neo4j):
    load_fixture(clean_neo4j, "mssql_ntlm_relay.cypher")

    findings = run_check(MSSQLNTLMRelayCheck, clean_neo4j, domain_filter="TEST.LOCAL")
    assert findings, "mssql_ntlm_relay should fire when a server has a service account and relay targets exist"

    host_sid = "S-1-5-21-TEST-3001"
    assert host_sid in findings
    detail = findings[host_sid]
    assert "xp_dirtree" in detail
    assert "SQLSVC@TEST.LOCAL" in detail
    assert "WEB01.TEST.LOCAL" in detail
