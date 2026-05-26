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
    assert "LinkedServer" not in keys    # non-principal Base/OpenGraph nodes excluded

    sample = findings["DOMAIN USERS@TEST.LOCAL HAS GENERICALL ON OU: WORKSTATIONS@TEST.LOCAL"]
    assert isinstance(sample, dict) and "inline_description" in sample


def test_falls_back_to_objectids_for_missing_names(clean_neo4j):
    load_fixture(clean_neo4j, "bad_successor_fallback_names.cypher")

    findings = run_check(BadSuccessorCheck, clean_neo4j, domain_filter="TEST.LOCAL")
    keys = "\n".join(findings)

    assert len(findings) == 3
    assert "None" not in keys
    assert "S-1-5-21-TEST-2001 HAS GENERICALL ON OU: WORKSTATIONS@TEST.LOCAL" in findings
    assert "S-1-5-21-TEST-2002 HAS GENERICALL ON OU: WORKSTATIONS@TEST.LOCAL" in findings
    assert "NAMED@TEST.LOCAL HAS GENERICALL ON OU: TEST-OU-NONAME" in findings


def test_requires_2025_dc_in_filtered_domain(clean_neo4j):
    load_fixture(clean_neo4j, "bad_successor_foreign_dc.cypher")

    findings = run_check(BadSuccessorCheck, clean_neo4j, domain_filter="TEST.LOCAL")
    assert findings == {}
