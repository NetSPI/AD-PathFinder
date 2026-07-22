import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from .dependencies import CheckDependencies
from .constants import DataTypes, EntityTypes
from .datasource import DataSourceRegistry

class VulnerabilityFrameworkManager:

    def __init__(self, neo4j_data, has_escalation_path_results=None, full_escalation_cache=None,
                 account_analysis=None, diagnostics=None):
        self.neo4j_data = neo4j_data
        self.account_analysis = account_analysis
        self._diagnostics = diagnostics
        self._diagnostic_domain = getattr(neo4j_data, '_domain_filter', None)
        self._diagnostic_query_start_index = 0
        self.shared_cache = {
            DataTypes.ESCALATION_PATHS: has_escalation_path_results or {},
            DataTypes.FULL_ESCALATION_PATHS: full_escalation_cache or {}
        }

        self.dependencies = CheckDependencies(
            neo4j_data=neo4j_data,
            shared_cache=self.shared_cache,
            account_analysis=account_analysis
        )

        self.display_content = {}
        self.stats_content = {}
        self._datasource_availability = {}
        
    def run_all_checks(self):
        from checks.core.registry import CheckRegistry

        self._record_import_errors()
        self._preload_required_data()
        self._check_datasource_availability()

        if self._diagnostics:
            self._diagnostic_query_start_index = len(self._diagnostics.queries)
            self._record_entity_summary()

        runnable = [c for c in CheckRegistry.get_all_checks() if not self._should_skip(c)]

        with ThreadPoolExecutor(max_workers=min(8, len(runnable) or 1)) as executor:
            futures = {executor.submit(self._run_single_check, c): c for c in runnable}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self._collect_result(result)

        self._sort_checks_by_priority()

        if self._diagnostics:
            for risk_level, blocks in self.display_content.items():
                self._diagnostics.check_order[risk_level] = [
                    b['check_instance'].__class__.__name__ for b in blocks
                ]
            self._record_platform_summary()

        return self.display_content, self.stats_content
    
    def _record_import_errors(self):
        if not self._diagnostics:
            return
        import checks
        import checks.cross_domain
        seen = {e["source"] for e in self._diagnostics.errors}
        for pkg, prefix in ((checks, "checks"), (checks.cross_domain, "checks.cross_domain")):
            for entry in getattr(pkg, "IMPORT_ERRORS", []):
                source = f"import:{prefix}.{entry['module']}"
                if source in seen:
                    continue
                self._diagnostics.record_error(
                    source,
                    f"{entry['error_type']}: {entry['message']}"
                )
                seen.add(source)

    def _preload_required_data(self):
        from checks.core.registry import CheckRegistry

        required_data_types = self._collect_required_data_types(CheckRegistry.get_all_checks())

        for data_type in required_data_types:
            self._preload_data_type(data_type)

        self.neo4j_data.populate_group_sid_mappings()

        if hasattr(self.neo4j_data, 'get_admin_users_and_computers'):
            self.neo4j_data.get_admin_users_and_computers()
    
    def _collect_required_data_types(self, check_classes):
        required_types = set()
        for check_class in check_classes:
            check_requirements = getattr(check_class, 'REQUIRED_DATA', [])
            required_types.update(check_requirements)
        return required_types
    
    def _preload_data_type(self, data_type):
        if data_type in self.shared_cache:
            return
            
        loader_methods = {
            DataTypes.COMPUTERS: 'get_all_computers_with_attributes',
            DataTypes.USERS: 'get_all_users_with_attributes', 
            DataTypes.ENTERPRISE_CAS: 'get_all_enterprise_cas_with_attributes',
            DataTypes.BAD_SUCCESSOR_OU_PRIVILEGES: 'get_bad_successor_ou_privileges'
        }
        
        method_name = loader_methods.get(data_type)
        if method_name and hasattr(self.neo4j_data, method_name):
            try:
                loader_method = getattr(self.neo4j_data, method_name)
                self.shared_cache[data_type] = loader_method()
            except Exception as e:
                print(f"Warning: failed to preload {data_type}: {e}")
                if self._diagnostics:
                    self._diagnostics.record_error(
                        f"preload:{data_type}",
                        e,
                        domain=self._diagnostic_domain
                    )

    def _check_datasource_availability(self):
        import datasources
        for name, ds_class in DataSourceRegistry.get_all().items():
            try:
                ds = ds_class(self.dependencies)
                self._datasource_availability[name] = ds.available()
            except Exception as e:
                print(f"Warning: DataSource {name} availability check failed: {e}")
                if self._diagnostics:
                    self._diagnostics.record_error(
                        f"datasource:{name}",
                        e,
                        domain=self._diagnostic_domain
                    )
                self._datasource_availability[name] = False

    def _should_skip(self, check_class):
        requires = getattr(check_class, 'REQUIRES', None)
        if not requires:
            return False
        for req in requires:
            if req not in self._datasource_availability:
                print(f"Warning: {check_class.__name__} requires unknown DataSource '{req}'; skipping check")
                if self._diagnostics:
                    self._diagnostics.record_skipped(
                        check_class.__name__,
                        f"unknown_requirement:{req}",
                        domain=self._diagnostic_domain
                    )
                return True
            if not self._datasource_availability[req]:
                if self._diagnostics:
                    self._diagnostics.record_skipped(
                        check_class.__name__,
                        f"datasource_unavailable:{req}",
                        domain=self._diagnostic_domain
                    )
                return True
        return False

    def _run_single_check(self, check_class):
        start = time.time()
        try:
            check_instance = check_class(self.dependencies)
            results = check_instance.run()
            duration_ms = (time.time() - start) * 1000

            return {
                'check_class': check_class,
                'check_instance': check_instance,
                'results': results,
                'duration_ms': duration_ms,
            }
        except Exception as e:
            duration_ms = (time.time() - start) * 1000
            if self._diagnostics:
                self._diagnostics.record_error(
                    f"check:{check_class.__name__}",
                    e,
                    domain=self._diagnostic_domain
                )
            self._handle_check_error(check_class, e)
            return None

    def _collect_result(self, result):
        check_class = result['check_class']
        check_instance = result['check_instance']
        results = result['results']

        if results:
            risk_level = check_class.RISK_LEVEL
            category_name = check_class.CATEGORY_NAME

            if risk_level not in self.display_content:
                self.display_content[risk_level] = []
                self.stats_content[risk_level] = {}

            count = check_instance.get_count(results)

            self.display_content[risk_level].append({
                'category': category_name,
                'count': count,
                'results': results,
                'check_instance': check_instance
            })

            self.stats_content[risk_level][category_name] = {
                'count': count,
                'results': results,
                'entity_type': getattr(check_class, 'ENTITY_TYPE', EntityTypes.COMPUTER),
            }

        if self._diagnostics:
            findings_count = check_instance.get_count(results) if results else 0
            finding_sids = list(results.keys()) if isinstance(results, dict) else None
            self._diagnostics.record_check(
                name=check_class.__name__,
                risk_level=check_class.RISK_LEVEL,
                category=check_class.CATEGORY_NAME,
                entity_type=getattr(check_class, 'ENTITY_TYPE', EntityTypes.COMPUTER),
                duration_ms=result['duration_ms'],
                entities_input=getattr(check_instance, '_entities_input', 0),
                entities_after_filter=getattr(check_instance, '_entities_after_filter', 0),
                filtered_breakdown=getattr(check_instance, '_filter_stats', {}),
                findings_count=findings_count,
                finding_sids=finding_sids,
                domain=self._diagnostic_domain
            )
    
    def _sort_checks_by_priority(self):
        from .constants import DisplayTypes

        display_type_order = {
            DisplayTypes.GROUP_ANALYSIS: 0,
            DisplayTypes.GROUPED_ESCALATION_PATHS: 1,
            DisplayTypes.ESCALATION_PATHS: 2,
        }

        def sort_key(check_block):
            check_instance = check_block['check_instance']
            display_type = getattr(check_instance, 'DISPLAY_TYPE', None)
            return (display_type_order.get(display_type, 3), check_block['category'])

        for risk_level in self.display_content:
            self.display_content[risk_level].sort(key=sort_key)

    def _handle_check_error(self, check_class, error):
        print(f"Error running check {check_class.__name__}: {error}")

    def _record_entity_summary(self):
        summary = self.neo4j_data.get_entity_counts()
        users = self.shared_cache.get(DataTypes.USERS)
        if users and "users" in summary:
            summary["users"]["admin"] = sum(1 for u in users if u.get('isAdmin') and not u.get('is_computer'))
        if summary:
            domain_key = self._diagnostic_domain or self.neo4j_data.get_domain_name()
            self._diagnostics.entity_summary[domain_key] = summary

    def _record_platform_summary(self):
        domain_checks = [c for c in self._diagnostics.checks if c.get('domain') == self._diagnostic_domain]
        mssql = [c for c in domain_checks if 'MSSQL' in (c.get('category') or '')]
        sccm = [c for c in domain_checks if 'SCCM' in (c.get('category') or '')]
        if not mssql and not sccm:
            return
        domain_key = self._diagnostic_domain or self.neo4j_data.get_domain_name()
        queries = self._diagnostics.queries[self._diagnostic_query_start_index:]
        bucket = {}
        if mssql:
            bucket["mssql"] = self._platform_perf_summary(
                mssql,
                self._queries_matching(queries, ("mssql",))
            )
        if sccm:
            bucket["sccm"] = self._platform_perf_summary(
                sccm,
                self._queries_matching(
                    queries,
                    ("sccm", "takeover", "elevate", "pxe", "management_points")
                )
            )
        self._diagnostics.mssql_sccm[domain_key] = bucket

    def _queries_matching(self, queries, markers):
        return [
            q for q in queries
            if any(marker in (q.get("name") or "").lower() for marker in markers)
        ]

    def _platform_perf_summary(self, checks, queries):
        slowest_check = max(checks, key=lambda c: c.get('duration_ms') or 0)
        summary = {
            "checks_run": len(checks),
            "total_findings": sum(c['findings_count'] for c in checks),
            "check_duration_ms": round(sum(c.get('duration_ms') or 0 for c in checks), 1),
            "slowest_check": {
                "name": slowest_check.get("name"),
                "duration_ms": slowest_check.get("duration_ms") or 0,
            },
            "queries_run": len(queries),
            "query_duration_ms": round(sum(q.get('duration_ms') or 0 for q in queries), 1),
            "slowest_query": None,
        }
        if queries:
            slowest_query = max(queries, key=lambda q: q.get('duration_ms') or 0)
            summary["slowest_query"] = {
                "name": slowest_query.get("name"),
                "duration_ms": slowest_query.get("duration_ms") or 0,
                "result_count": slowest_query.get("result_count") or 0,
            }
        return summary
