import pytest

from checks.sccm_pxe_dp import SCCMPxeDPCheck
from tests.check_harness import load_fixture, run_check

pytestmark = pytest.mark.neo4j


def test_fires_on_distribution_point(clean_neo4j):
    load_fixture(clean_neo4j, "sccm_pxe_dp.cypher")

    findings = run_check(SCCMPxeDPCheck, clean_neo4j, domain_filter="TEST.LOCAL")
    assert findings, "Should flag distribution point for PXE boot review"
    assert "S-1-5-21-TEST-1400" in findings
