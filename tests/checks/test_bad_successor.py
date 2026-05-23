import pytest

from checks.bad_successor import BadSuccessorCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_flags_non_tier0_control_of_ous_and_containers(clean_neo4j):
    load_fixture(clean_neo4j, "bad_successor.cypher")

    findings = run_check(BadSuccessorCheck, clean_neo4j, domain_filter="TEST.LOCAL")
    assert BadSuccessorCheck.RISK_LEVEL == "High"
    assert len(findings) == 2

    assert "DOMAIN USERS@TEST.LOCAL HAS GENERICALL ON OU: WORKSTATIONS@TEST.LOCAL" in findings
    assert ("HELPDESK@TEST.LOCAL HAS WRITEDACL ON CONTAINER: "
            "MANAGED SERVICE ACCOUNTS@TEST.LOCAL") in findings

    keys = "\n".join(findings)
    assert "STALE" not in keys          # disabled principal excluded
    assert "DOMAIN ADMINS" not in keys  # Tier-0 principal excluded
    assert "OTHER.LOCAL" not in keys    # different-domain targets excluded

    sample = findings["DOMAIN USERS@TEST.LOCAL HAS GENERICALL ON OU: WORKSTATIONS@TEST.LOCAL"]
    assert isinstance(sample, dict) and "inline_description" in sample


def test_requires_2025_dc_in_filtered_domain(clean_neo4j):
    load_fixture(clean_neo4j, "bad_successor_foreign_dc.cypher")

    findings = run_check(BadSuccessorCheck, clean_neo4j, domain_filter="TEST.LOCAL")
    assert findings == {}
