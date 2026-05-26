import pytest

from checks.tier0_session_exposure import Tier0SessionExposureCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_tier0_session_on_non_tier0_host(clean_neo4j):
    load_fixture(clean_neo4j, "tier0_session_exposure.cypher")

    findings = run_check(Tier0SessionExposureCheck, clean_neo4j, domain_filter="TEST.LOCAL")
    assert Tier0SessionExposureCheck.RISK_LEVEL == "Low"
    assert len(findings) == 1

    user_sid = "S-1-5-21-TEST-4001"
    assert user_sid in findings
    detail = findings[user_sid]
    assert isinstance(detail, dict) and "details" in detail
    assert "hosts" in detail["details"]
    assert "WS01.TEST.LOCAL" in detail["details"]["hosts"]


def test_silent_when_computer_is_also_tier0(clean_neo4j):
    load_fixture(clean_neo4j, "tier0_session_exposure_tier0_computer.cypher")
    findings = run_check(Tier0SessionExposureCheck, clean_neo4j, domain_filter="TEST.LOCAL")
    assert not findings, "tier0_session_exposure must not fire when session is on a tier-0 host"
