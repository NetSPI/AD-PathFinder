from pathlib import Path
from types import SimpleNamespace

import datasources as _datasources_pkg  # noqa: F401 — triggers @datasource registration
from checks.core.datasource import DataSourceRegistry
from checks.core.dependencies import CheckDependencies
from modules.neo4j_data import Neo4jData


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(conn, fixture_name):
    path = FIXTURES_DIR / fixture_name
    cypher = path.read_text()
    for stmt in cypher.split(";"):
        stmt = stmt.strip()
        if stmt:
            conn.query(stmt)


def _assert_datasource_requirements(check_class, dependencies):
    requires = getattr(check_class, 'REQUIRES', None)
    if not requires:
        return
    all_ds = DataSourceRegistry.get_all()
    for req in requires:
        ds_class = all_ds.get(req)
        assert ds_class is not None, (
            f"{check_class.__name__} requires unknown datasource '{req}'"
        )
        ds = ds_class(dependencies)
        assert ds.available(), (
            f"{check_class.__name__} requires datasource '{req}' but it is not "
            f"available — fixture is missing the sentinel node "
            f"(SCCM_Site for sccm, MSSQL_Server for mssql)"
        )


def run_check(
    check_class,
    conn,
    *,
    excluded_relationships=None,
    domain_filter=None,
    shared_cache=None,
    account_analysis=None,
    preload_entity_sid_mappings=False,
):
    neo4j_data = Neo4jData(
        conn,
        excluded_relationships=excluded_relationships or [],
        domain_filter=domain_filter,
        diagnostics=None,
    )
    neo4j_data.populate_group_sid_mappings()

    if preload_entity_sid_mappings:
        neo4j_data.get_all_users_with_attributes(skip_high_value=True)

    dependencies = CheckDependencies(
        neo4j_data=neo4j_data,
        shared_cache=shared_cache or {},
        account_analysis=account_analysis,
    )
    _assert_datasource_requirements(check_class, dependencies)
    check = check_class(dependencies)
    return check.run()


def build_fake_account_analysis(
    *,
    weak_passwords=None,
    cracked_accounts=None,
    user_details_mapping=None,
    users_in_shared_accounts=None,
    output_format="safe",
    all_user_data=None,
    normalise_path=None,
):
    weak = {str(v).lower() for v in (weak_passwords or [])}
    return SimpleNamespace(
        _has_weak_password=lambda username: str(username).lower() in weak,
        cracked_accounts=cracked_accounts or {},
        user_details_mapping=user_details_mapping or {},
        users_in_shared_accounts=users_in_shared_accounts or set(),
        output_format=output_format,
        get_all_user_data=lambda: list(all_user_data or []),
        normalise_path=normalise_path or (lambda path: " -> ".join(str(p) for p in path)),
    )
