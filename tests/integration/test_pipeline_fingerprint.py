import json
import os
from pathlib import Path
from urllib.parse import urlparse

import pytest

from modules.neo4j_connection import Neo4jConnection
from modules.neo4j_data import Neo4jData
from modules.BloodhoundImporter import BloodhoundImporter
from modules.account_analysis import AccountAnalysis
from modules.analysis import Analysis
from modules.diagnostics import DiagnosticsCollector
from modules.main import run_client_report_generation
from modules.reporting import Reporting
from modules.utils import (
    load_ntds_hashes_with_metadata,
    parse_potfile_partitioned,
    partition_ntds_by_domain,
)


def _load_ntds_for_domain(neo4j_data, ntds_path):
    entries = load_ntds_hashes_with_metadata(str(ntds_path))
    rid_map, prefix_map = neo4j_data.build_rid_to_domain_map()
    all_domains = neo4j_data.get_all_domain_names()
    domain_hashes = partition_ntds_by_domain(entries, rid_map, prefix_map, all_domains)
    return domain_hashes.get(neo4j_data.get_domain_name(), ({}, {}))

pytestmark = [pytest.mark.integration, pytest.mark.neo4j]

SAMPLE_DIR = Path(__file__).resolve().parent.parent.parent / "sample_data"

REQUIRED_ENV = ("BH_USER", "BH_PASSWORD",
                "NEO4J_URI", "NEO4J_USER", "NEO4J_PASSWORD")


def _missing_env():
    return [v for v in REQUIRED_ENV if not os.environ.get(v)]


skip_unless_configured = pytest.mark.skipif(
    bool(_missing_env()),
    reason=f"Integration env vars missing: {', '.join(_missing_env())}",
)

EXPECTED_NODE_LABELS = [
    "Domain", "User", "Computer", "Group",
    "CertTemplate", "EnterpriseCA",
    "MSSQL_Server", "SCCM_Site",
]

EXPECTED_REL_TYPES = [
    "MemberOf", "AdminTo", "HasSession", "GenericAll",
    "MSSQL_HasLogin", "MSSQL_HostFor",
    "SCCM_AssignAllPermissions",
    "CoerceAndRelayToMSSQL", "CoerceAndRelayToAdminService",
    "CoerceAndRelayToSMB",
]

SENTINEL_CATEGORIES = [
    "Admin with Weak Password",
    "Computer has Weak Password",
    "ESC1 — Enrollee Supplies Subject",
    "MSSQL Login",
    "MSSQL Privilege Escalation",
    "SCCM Privilege Escalation",
    "KRBTGT Password Older Than 6 Months",
    "Computers with SMB Signing Disabled",
]

SCCM_TAKEOVER_PREFIX = "SCCM"
SCCM_TAKEOVER_MARKER = "TAKEOVER"
CLEAR_BATCH_SIZE = 250
CLEAR_MAX_BATCHES = 500
FORBIDDEN_AD_REPORT_LABELS = {
    "Base",
    "OpenGraph_Stub",
    "SCCM_Base",
    "MSSQL_Base",
    "MSSQL_Server",
    "MSSQL_Login",
    "MSSQL_Database",
    "MSSQL_ServerRole",
    "MSSQL_DatabaseRole",
    "MSSQL_DatabaseUser",
    "SCCM_Site",
}


def _bloodhound_default_port(uri):
    try:
        parsed = urlparse(uri)
    except Exception:
        return False
    host = (parsed.hostname or "").lower()
    return host in {"localhost", "127.0.0.1", "::1", "0.0.0.0"} and (parsed.port or 7687) == 7687


def _node_count(conn):
    result = conn.query("MATCH (n) RETURN count(n) AS c")
    return result[0]["c"] if result else 0


def _relationship_count(conn):
    result = conn.query("MATCH ()-[r]->() RETURN count(r) AS c")
    return result[0]["c"] if result else 0


def _clear_in_batches(conn, query, count_func, label):
    for _ in range(CLEAR_MAX_BATCHES):
        result = conn.query(query, parameters={"batch_size": CLEAR_BATCH_SIZE})
        deleted = result[0]["deleted"] if result else 0
        if deleted == 0:
            return
    remaining = count_func(conn)
    pytest.fail(
        f"Direct graph pre-clear exceeded {CLEAR_MAX_BATCHES} {label} batches; "
        f"{remaining} {label} remain"
    )


def _clear_graph_in_batches(conn):
    """Keep CE test clears below Neo4j's transaction memory cap."""
    _clear_in_batches(
        conn,
        """
        MATCH ()-[r]->()
        WITH r LIMIT $batch_size
        DELETE r
        RETURN count(r) AS deleted
        """,
        _relationship_count,
        "relationship",
    )
    _clear_in_batches(
        conn,
        """
        MATCH (n)
        WITH n LIMIT $batch_size
        DELETE n
        RETURN count(n) AS deleted
        """,
        _node_count,
        "node",
    )


def _scan_json_for_forbidden_labels(value, path="$"):
    problems = []
    if isinstance(value, dict):
        for key, child in value.items():
            problems.extend(_scan_json_for_forbidden_labels(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            problems.extend(_scan_json_for_forbidden_labels(child, f"{path}[{index}]"))
    elif isinstance(value, str) and value in FORBIDDEN_AD_REPORT_LABELS:
        problems.append(f"{path}={value!r}")
    return problems


@pytest.fixture(scope="module")
def neo4j_conn():
    if os.environ.get("ADPF_TEST_ALLOW_WIPE") != "1":
        pytest.fail(
            "Refusing to run pipeline test: ADPF_TEST_ALLOW_WIPE=1 is not set. "
            "This test clears the configured Neo4j database directly. "
            "Set the env var only when targeting a disposable test instance."
        )

    uri = os.environ["NEO4J_URI"]

    if _bloodhound_default_port(uri):
        in_ci = os.environ.get("GITHUB_ACTIONS") == "true"
        force = os.environ.get("ADPF_TEST_FORCE_DEFAULT_PORT") == "1"
        if not (in_ci or force):
            pytest.fail(
                f"Refusing to wipe {uri}: that is the BloodHound default port and "
                "almost certainly a real instance. Point NEO4J_URI at a disposable "
                "container (e.g. port 17687), or set ADPF_TEST_FORCE_DEFAULT_PORT=1."
            )

    user = os.environ["NEO4J_USER"]
    password = os.environ["NEO4J_PASSWORD"]
    conn = Neo4jConnection(uri, user, password)
    assert conn.is_connected(), f"Neo4j not reachable at {uri}"
    yield conn
    conn.close()


@pytest.fixture(scope="module")
def importer(neo4j_conn):
    return BloodhoundImporter(
        neo4j_conn,
        bloodhound_username=os.environ["BH_USER"],
        bloodhound_password=os.environ["BH_PASSWORD"],
        base_url=os.environ.get("BH_URL", "http://localhost:8080"),
    )


@pytest.fixture(scope="module")
def imported_dataset(importer, neo4j_conn):
    _clear_graph_in_batches(neo4j_conn)

    neo4j_data = Neo4jData(neo4j_conn)
    assert _node_count(neo4j_conn) == 0, "Direct graph clear left nodes behind"
    assert neo4j_data.get_domain_name(force_refresh=True) == "Unknown Domain"

    zip_paths = [
        str(SAMPLE_DIR / "SharpHound.zip"),
        str(SAMPLE_DIR / "MSSQLHound.zip"),
        str(SAMPLE_DIR / "ConfigManBearPig.zip"),
    ]
    for zp in zip_paths:
        assert Path(zp).is_file(), f"Sample data missing: {zp}"

    assert importer.import_zip(zip_paths), "import_zip() returned False"

    return neo4j_data


@pytest.fixture(scope="module")
def pipeline_result(imported_dataset):
    ntds_path = SAMPLE_DIR / "ntds.txt"
    potfile_path = SAMPLE_DIR / "hashcat.potfile"
    assert ntds_path.is_file(), f"Missing {ntds_path}"
    assert potfile_path.is_file(), f"Missing {potfile_path}"

    ntds_data = _load_ntds_for_domain(imported_dataset, ntds_path)

    cracked_hashes, ntlmv2_hashes = parse_potfile_partitioned(str(potfile_path))

    diagnostics = DiagnosticsCollector()
    account_analysis = AccountAnalysis(
        cracked_hashes, ntlmv2_hashes, ntds_data, imported_dataset,
        diagnostics=diagnostics,
    )

    _, organised_risk_profiles = account_analysis.create_risk_profiles(
        shared_accounts_summary={},
    )

    return {
        "neo4j_data": imported_dataset,
        "account_analysis": account_analysis,
        "diagnostics": diagnostics,
        "organised_risk_profiles": organised_risk_profiles,
    }


@skip_unless_configured
class TestPipelineImport:

    def test_import_produced_domain(self, imported_dataset):
        domain = imported_dataset.get_domain_name(force_refresh=True)
        assert domain != "Unknown Domain", (
            "Import completed but no domain found in Neo4j"
        )


@skip_unless_configured
class TestGraphSanity:

    @pytest.mark.parametrize("label", EXPECTED_NODE_LABELS)
    def test_node_label_exists(self, imported_dataset, label):
        result = imported_dataset.conn.query(
            f"MATCH (n:{label}) RETURN count(n) AS c"
        )
        count = result[0]["c"] if result else 0
        assert count > 0, f"No :{label} nodes found after import"

    @pytest.mark.parametrize("rel_type", EXPECTED_REL_TYPES)
    def test_relationship_type_exists(self, imported_dataset, rel_type):
        result = imported_dataset.conn.query(
            f"MATCH ()-[r:{rel_type}]->() RETURN count(r) AS c"
        )
        count = result[0]["c"] if result else 0
        assert count > 0, f"No [:{rel_type}] relationships found after import"

    def test_opengraph_stubs_do_not_carry_base_label(self, imported_dataset):
        result = imported_dataset.conn.query(
            "MATCH (n:OpenGraph_Stub:Base) RETURN count(n) AS c"
        )
        count = result[0]["c"] if result else 0
        assert count == 0, "OpenGraph fallback stubs should not carry :Base"


@skip_unless_configured
class TestFullPipeline:

    def test_framework_checks_ran(self, pipeline_result):
        aa = pipeline_result["account_analysis"]
        stats = getattr(aa, "_framework_categories_for_stats", {})
        total_categories = sum(len(cats) for cats in stats.values())
        assert total_categories > 0, (
            "_framework_categories_for_stats is empty — framework checks did not run"
        )

    def test_diagnostics_recorded_checks(self, pipeline_result):
        checks = pipeline_result["diagnostics"].checks
        assert len(checks) > 0, "diagnostics.checks is empty — no checks were recorded"


@skip_unless_configured
class TestDiagnostics:

    def test_no_errors(self, pipeline_result):
        errors = pipeline_result["diagnostics"].errors
        assert errors == [], (
            f"Pipeline produced {len(errors)} diagnostic error(s):\n"
            + "\n".join(f"  [{e.get('source', '?')}] {e.get('error', '')}" for e in errors)
        )


@skip_unless_configured
class TestCategoryFingerprint:

    @pytest.mark.parametrize("category", SENTINEL_CATEGORIES)
    def test_sentinel_category_has_findings(self, pipeline_result, category):
        stats = pipeline_result["account_analysis"]._framework_categories_for_stats
        all_categories = {}
        for level_cats in stats.values():
            all_categories.update(level_cats)

        assert category in all_categories, (
            f"Sentinel category '{category}' missing from framework stats. "
            f"Present categories: {sorted(all_categories.keys())}"
        )
        assert all_categories[category]["count"] > 0, (
            f"Sentinel category '{category}' has 0 findings"
        )

    def test_at_least_one_sccm_takeover(self, pipeline_result):
        stats = pipeline_result["account_analysis"]._framework_categories_for_stats
        all_categories = {}
        for level_cats in stats.values():
            all_categories.update(level_cats)

        takeover_hits = {
            cat: info["count"]
            for cat, info in all_categories.items()
            if SCCM_TAKEOVER_PREFIX in cat and SCCM_TAKEOVER_MARKER in cat
            and info["count"] > 0
        }
        assert takeover_hits, (
            "No SCCM TAKEOVER category produced findings. "
            f"SCCM categories present: {[c for c in all_categories if 'SCCM' in c]}"
        )


@skip_unless_configured
class TestNoUnexpectedSkips:

    def test_no_skipped_checks(self, pipeline_result):
        skipped = pipeline_result["diagnostics"].skipped
        assert skipped == [], (
            f"Checks were unexpectedly skipped after full import: {skipped}"
        )


@skip_unless_configured
class TestReportArtifacts:

    def test_ad_report_artifacts_do_not_render_opengraph_labels(
        self,
        imported_dataset,
        tmp_path,
        monkeypatch,
    ):
        monkeypatch.chdir(tmp_path)

        ntds_data = _load_ntds_for_domain(imported_dataset, SAMPLE_DIR / "ntds.txt")
        cracked_hashes, ntlmv2_hashes = parse_potfile_partitioned(
            str(SAMPLE_DIR / "hashcat.potfile")
        )
        diagnostics = DiagnosticsCollector()
        account_analysis = AccountAnalysis(
            cracked_hashes,
            ntlmv2_hashes,
            ntds_data,
            imported_dataset,
            diagnostics=diagnostics,
        )
        analysis = Analysis(
            imported_dataset,
            cracked_hashes,
            ntlmv2_hashes,
            ntds_data,
            account_analysis=account_analysis,
        )
        reporting = Reporting(account_analysis, analysis)

        reporting.generate_full_report(["TEST", "NetSPI"])
        domain = imported_dataset.get_domain_name(force_refresh=True)
        report_dir = tmp_path / f"report_{domain.lower()}"
        run_client_report_generation(str(report_dir), domain)

        domain_json = report_dir / f"{domain.lower()}_domain_audit.json"
        domain_text = report_dir / f"{domain.lower()}_domain_audit.txt"
        ad_html = report_dir / f"{domain.lower()}_AD_report.html"
        for artifact in (domain_json, domain_text, ad_html):
            assert artifact.is_file(), f"Missing generated artifact: {artifact}"

        problems = []
        domain_data = json.loads(domain_json.read_text(encoding="utf-8"))
        problems.extend(_scan_json_for_forbidden_labels(domain_data))

        text_patterns = {f"({label})" for label in FORBIDDEN_AD_REPORT_LABELS}
        html_patterns = text_patterns | {
            f">{label}</text>" for label in FORBIDDEN_AD_REPORT_LABELS
        } | {
            f"Type: {label}" for label in FORBIDDEN_AD_REPORT_LABELS
        }
        for artifact, patterns in (
            (domain_text, text_patterns),
            (ad_html, html_patterns),
        ):
            content = artifact.read_text(encoding="utf-8", errors="ignore")
            for pattern in sorted(patterns):
                if pattern in content:
                    problems.append(f"{artifact.name}: contains {pattern!r}")

        assert problems == []
