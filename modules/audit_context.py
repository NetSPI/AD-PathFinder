import os

from .neo4j_connection import InstrumentedConnection
from .neo4j_data import Neo4jData
from .utils import (
    load_ntds_hashes_with_metadata,
    parse_potfile_partitioned,
    partition_ntds_by_domain,
)


_UNSET = object()


class MultiDomainAuditContext:

    def __init__(self, conn, unscoped_neo4j_data, excluded_relationships,
                 hashcat_file_path, ntds_file_path, diagnostics):
        self.conn = conn
        self.diagnostics = diagnostics
        self.excluded_relationships = excluded_relationships
        self.ntds_file_path = ntds_file_path
        if hashcat_file_path and os.path.isfile(hashcat_file_path):
            self.hashcat_file_path = hashcat_file_path
        else:
            self.hashcat_file_path = None

        self._unscoped = unscoped_neo4j_data

        self._all_domains = _UNSET
        self._relationship_pattern = _UNSET
        self._potfile = _UNSET
        self._ntds_loaded = False
        self._ntds_entries_count = 0
        self._domain_hashes = {}
        self._per_domain_admin_users = _UNSET
        self._cross_domain_results = _UNSET
        self._domain_neo4j_data = {}

        try:
            from checks.cross_domain.base import CrossDomainDependencies
            from checks.cross_domain.manager import CrossDomainManager
            import checks.cross_domain as cross_domain_pkg
        except ImportError as e:
            print(f"Warning: Cross-domain checks unavailable: {e}")
            if diagnostics:
                diagnostics.record_error("import:checks.cross_domain", e)
            self._cd_deps_cls = None
            self._cd_manager_cls = None
            self._cross_domain_pkg = None
        else:
            self._cd_deps_cls = CrossDomainDependencies
            self._cd_manager_cls = CrossDomainManager
            self._cross_domain_pkg = cross_domain_pkg

    @property
    def all_domains(self):
        if self._all_domains is _UNSET:
            self._all_domains = list(self._unscoped.get_all_domain_names())
        return self._all_domains

    @property
    def relationship_pattern(self):
        if self._relationship_pattern is _UNSET:
            self._relationship_pattern = self._unscoped.get_all_relationships()
        return self._relationship_pattern

    @property
    def domain_hashes(self):
        self._ensure_ntds_loaded()
        return self._domain_hashes

    @property
    def ntds_entries_loaded(self):
        self._ensure_ntds_loaded()
        return self._ntds_entries_count > 0

    def _ensure_ntds_loaded(self):
        if self._ntds_loaded:
            return
        self._ntds_loaded = True
        if not self.ntds_file_path:
            return
        rid_map, prefix_map = self._unscoped.build_rid_to_domain_map()
        ntds_entries = load_ntds_hashes_with_metadata(self.ntds_file_path)
        self._ntds_entries_count = len(ntds_entries) if ntds_entries else 0
        if ntds_entries:
            self._domain_hashes = partition_ntds_by_domain(
                ntds_entries, rid_map, prefix_map, self.all_domains
            )

    @property
    def cracked_passwords_global(self):
        return self._get_potfile()[0]

    def get_ntlmv2_hashes_for_domain(self, domain):
        _, by_netbios = self._get_potfile()
        netbios = (domain or "").upper().split('.')[0]
        return by_netbios.get(netbios, {})

    def _get_potfile(self):
        if self._potfile is _UNSET:
            if self.hashcat_file_path:
                try:
                    self._potfile = parse_potfile_partitioned(self.hashcat_file_path)
                except Exception as e:
                    print(f"Failed to load cracked hashes: {e}")
                    self._potfile = ({}, {})
            else:
                self._potfile = ({}, {})
        return self._potfile

    def get_domain_neo4j_data(self, domain):
        if domain not in self._domain_neo4j_data:
            self._domain_neo4j_data[domain] = Neo4jData(
                self.conn,
                excluded_relationships=self.excluded_relationships,
                domain_filter=domain,
                diagnostics=self.diagnostics,
            )
        return self._domain_neo4j_data[domain]

    @property
    def per_domain_admin_users(self):
        if self._per_domain_admin_users is _UNSET:
            result = {}
            for domain in self.all_domains:
                neo4j_data_domain = self.get_domain_neo4j_data(domain)
                admin_users, _ = neo4j_data_domain.get_admin_users_and_computers()
                if admin_users:
                    result[domain] = set(u.split('@')[0].lower() for u in admin_users)
                else:
                    result[domain] = set()
            self._per_domain_admin_users = result
        return self._per_domain_admin_users

    @property
    def cross_domain_results(self):
        if self._cross_domain_results is _UNSET:
            self._cross_domain_results = self._run_cross_domain()
        return self._cross_domain_results

    def _run_cross_domain(self):
        if self._cd_manager_cls is None:
            return {}

        _record_cross_domain_import_errors(self.diagnostics, self._cross_domain_pkg)

        if self.diagnostics:
            deps_conn = InstrumentedConnection(self.conn, self.diagnostics)
        else:
            deps_conn = self.conn

        deps = self._cd_deps_cls(
            conn=deps_conn,
            all_domains=self.all_domains,
            domain_hashes=self.domain_hashes,
            cracked_hashes=self.cracked_passwords_global,
            per_domain_admin_users=self.per_domain_admin_users,
            relationship_pattern=self.relationship_pattern,
            diagnostics=self.diagnostics,
        )
        manager = self._cd_manager_cls(deps, diagnostics=self.diagnostics)
        return manager.run_all_checks()


def _record_cross_domain_import_errors(diagnostics, cross_domain_pkg):
    if not diagnostics or cross_domain_pkg is None:
        return

    seen = {e["source"] for e in diagnostics.errors}
    for entry in getattr(cross_domain_pkg, "IMPORT_ERRORS", []):
        source = f"import:checks.cross_domain.{entry['module']}"
        if source in seen:
            continue
        diagnostics.record_error(
            source,
            f"{entry['error_type']}: {entry['message']}"
        )
        seen.add(source)
