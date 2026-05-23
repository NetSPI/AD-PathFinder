"""Asserts every registered check has a test and fixture, or is allow-listed."""

from pathlib import Path

import checks  # noqa: F401 — triggers @check registration
import checks.cross_domain  # noqa: F401 — triggers @CrossDomainRegistry.register
from checks.core.registry import CheckRegistry
from checks.cross_domain.base import CrossDomainRegistry

TESTS_DIR = Path(__file__).parent / "checks"
CROSS_DOMAIN_TESTS_DIR = TESTS_DIR / "cross_domain"
FIXTURES_DIR = Path(__file__).parent / "fixtures"

EXTRA_TEST_FILES = {"test_manager_smoke.py"}

EXTRA_FIXTURES = {
    "sccm_takeover7_disabled_host",
    "esc1_vulnerable_template_manager_approval",
    "esc3_enrollment_agent_manager_approval",
    "esc6_user_specifies_san_manager_approval",
    "esc9_no_security_extension_auth_disabled",
    "tier0_session_exposure_tier0_computer",
    "cross_domain_escalation_path_via_trust",
    "cross_domain_computer_escalation_path_via_trust",
    "dedupe_mssql_servers",
    "canonicalize_linked_server",
    "mssql_privilege_escalation_linked_server",
    "mssql_priv_esc_group_owned_login",
    "mssql_priv_esc_linked_server_sid",
    "mssql_priv_esc_linked_server_overmatch",
    "mssql_priv_esc_linked_server_name_overmatch",
    "mssql_priv_esc_linked_server_empty_stub",
    "mssql_priv_esc_linked_server_shared_host_sid",
    "mssql_priv_esc_owns_server_role",
    "sccm_priv_esc_linked_server_name_overmatch",
    "sccm_priv_esc_linked_server_empty_stub",
    "sccm_priv_esc_linked_server_shared_host_sid",
}


def _registered_module_names():
    return {c.__module__.replace("checks.", "") for c in CheckRegistry.get_all_checks()}


def _cross_domain_module_names():
    return {
        c.__module__.replace("checks.cross_domain.", "")
        for c in CrossDomainRegistry.get_all_checks()
    }


# --- Standard checks (CheckRegistry) ---

def test_every_check_has_a_test_file():
    registered = _registered_module_names()
    test_files = {
        f.stem.removeprefix("test_")
        for f in TESTS_DIR.glob("test_*.py")
        if f.name not in EXTRA_TEST_FILES
    }
    missing = sorted(registered - test_files)
    assert not missing, f"Registered checks without a test file: {missing}"


def test_every_check_has_a_fixture_file():
    registered = _registered_module_names()
    fixture_files = {
        f.stem
        for f in FIXTURES_DIR.glob("*.cypher")
        if f.stem not in EXTRA_FIXTURES
    }
    missing = sorted(registered - fixture_files)
    assert not missing, f"Registered checks without a fixture file: {missing}"


def test_no_orphan_test_files():
    registered = _registered_module_names()
    test_files = {
        f.stem.removeprefix("test_")
        for f in TESTS_DIR.glob("test_*.py")
        if f.name not in EXTRA_TEST_FILES
    }
    orphans = sorted(test_files - registered)
    assert not orphans, f"Test files without a registered check: {orphans}"


def test_no_orphan_fixture_files():
    registered = _registered_module_names()
    cross_domain = _cross_domain_module_names()
    fixture_files = {
        f.stem
        for f in FIXTURES_DIR.glob("*.cypher")
        if f.stem not in EXTRA_FIXTURES
    }
    known = registered | cross_domain
    orphans = sorted(fixture_files - known)
    assert not orphans, f"Fixture files without a registered check: {orphans}"


# --- Cross-domain checks (CrossDomainRegistry) ---

def test_every_cross_domain_check_has_a_test_file():
    registered = _cross_domain_module_names()
    test_files = {
        f.stem.removeprefix("test_")
        for f in CROSS_DOMAIN_TESTS_DIR.glob("test_*.py")
    }
    missing = sorted(registered - test_files)
    assert not missing, f"Cross-domain checks without a test file: {missing}"


def test_no_orphan_cross_domain_test_files():
    registered = _cross_domain_module_names()
    test_files = {
        f.stem.removeprefix("test_")
        for f in CROSS_DOMAIN_TESTS_DIR.glob("test_*.py")
    }
    orphans = sorted(test_files - registered)
    assert not orphans, f"Cross-domain test files without a registered check: {orphans}"
