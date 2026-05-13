from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from .base import CrossDomainCheck, CrossDomainRegistry


@CrossDomainRegistry.register
class CrossDomainEscalationPathCheck(CrossDomainCheck):
    RISK_LEVEL = "Critical"
    CATEGORY_NAME = "Cross-Domain Escalation Paths"
    REQUIRES_NTDS = False
    BATCH_SIZE = 250

    def execute(self):
        rels = self.deps.relationship_pattern
        if not rels:
            return []

        user_sids = self._get_source_sids()
        if not user_sids:
            return []

        num_workers = self.deps.get_adaptive_workers(len(user_sids))

        da_findings = self._query_paths_batched(
            user_sids, rels, 'da', num_workers
        )
        users_with_da = {f['source_sid'] for f in da_findings}

        remaining_sids = [sid for sid in user_sids if sid not in users_with_da]
        tier0_findings = []
        if remaining_sids:
            tier0_findings = self._query_paths_batched(
                remaining_sids, rels, 'tier0', num_workers
            )

        return da_findings + tier0_findings

    def _get_source_sids(self):
        query = """
            MATCH (u:User)
            WHERE NOT u.name STARTS WITH 'KRBTGT'
            RETURN u.objectid AS sid, u.name AS name
        """
        try:
            results = self.deps.conn.query(query, name="cross_domain_user_paths_source_sids")
            if not results:
                return []

            per_domain = getattr(self.deps, 'per_domain_admin_users', None) or {}
            admin_by_domain = {
                d.upper(): {u.split('@')[0].lower() for u in users}
                for d, users in per_domain.items()
            }

            filtered = []
            for r in results:
                sid = r.get('sid')
                name = r.get('name') or ''
                if not sid or '@' not in name:
                    continue
                sam, _, dom = name.partition('@')
                if sam.lower() in admin_by_domain.get(dom.upper(), set()):
                    continue
                filtered.append(sid)
            return filtered
        except Exception as e:
            if self.deps.diagnostics:
                self.deps.diagnostics.record_error("cross_domain:user_paths.source_sids", e)
            return []

    def _query_paths_batched(self, sids, rels, target_type, num_workers):
        if not sids:
            return []

        batches = []
        for i in range(0, len(sids), self.BATCH_SIZE):
            batches.append(sids[i:i + self.BATCH_SIZE])

        if num_workers <= 1 or len(batches) <= 1:
            all_findings = []
            for batch in batches:
                findings = self._query_batch(batch, rels, target_type)
                all_findings.extend(findings)
            return all_findings

        all_findings = []
        worker_conns = []

        try:
            for _ in range(num_workers):
                worker_conns.append(self.deps.conn.get_connection_for_thread())

            with ThreadPoolExecutor(max_workers=num_workers) as executor:
                futures = {}
                for idx, batch in enumerate(batches):
                    conn = worker_conns[idx % num_workers]
                    future = executor.submit(
                        self._query_batch, batch, rels, target_type, conn
                    )
                    futures[future] = idx

                for future in as_completed(futures):
                    try:
                        findings = future.result()
                        all_findings.extend(findings)
                    except Exception as e:
                        if self.deps.diagnostics:
                            self.deps.diagnostics.record_error(
                                "cross_domain:user_paths.worker_future", e)

        finally:
            for conn in worker_conns:
                try:
                    self.deps.conn.return_connection_to_pool(conn)
                except Exception:
                    pass

        return all_findings

    def _query_batch(self, batch_sids, rels, target_type, conn=None):
        if conn is None:
            conn = self.deps.conn

        if target_type == 'da':
            query = f'''
                MATCH (target:Group)
                WHERE target.name STARTS WITH "DOMAIN ADMINS@"
                WITH collect(target) AS targets

                MATCH (source:User)
                WHERE source.objectid IN $batch_sids
                UNWIND targets AS target
                WITH source, target
                WHERE source.domain <> target.domain
                MATCH path = shortestPath((source)-[:{rels}*1..10]->(target))
                WITH source, target, path, length(path) AS pathLen
                ORDER BY pathLen
                WITH source, collect({{target: target, path: path, len: pathLen}})[0] AS shortest
                RETURN source.name AS source_user,
                       source.domain AS source_domain,
                       source.objectid AS source_sid,
                       shortest.target.name AS target_name,
                       shortest.target.domain AS target_domain,
                       [n IN nodes(shortest.path) | {{
                           name: n.name,
                           domain: n.domain,
                           labels: labels(n),
                           objectid: n.objectid
                       }}] AS path_nodes,
                       [r IN relationships(shortest.path) | type(r)] AS path_rels,
                       shortest.len AS path_length
            '''
            result_target_type = 'Domain Admin'
        else:
            query = f'''
                MATCH (target)
                WHERE "Tag_Tier_Zero" IN labels(target)
                  AND NOT target.name STARTS WITH "DOMAIN ADMINS@"
                  AND (
                      target:Computer OR
                      target:Domain OR
                      target.name STARTS WITH "ENTERPRISE ADMINS@" OR
                      target.name STARTS WITH "ADMINISTRATORS@" OR
                      target.name STARTS WITH "KRBTGT@"
                  )
                WITH collect(target) AS targets

                MATCH (source:User)
                WHERE source.objectid IN $batch_sids
                UNWIND targets AS target
                WITH source, target
                WHERE source.domain <> target.domain
                MATCH path = shortestPath((source)-[:{rels}*1..10]->(target))
                WITH source, target, path, length(path) AS pathLen
                ORDER BY pathLen
                WITH source, collect({{target: target, path: path, len: pathLen}})[0] AS shortest
                RETURN source.name AS source_user,
                       source.domain AS source_domain,
                       source.objectid AS source_sid,
                       shortest.target.name AS target_name,
                       shortest.target.domain AS target_domain,
                       labels(shortest.target) AS target_labels,
                       [n IN nodes(shortest.path) | {{
                           name: n.name,
                           domain: n.domain,
                           labels: labels(n),
                           objectid: n.objectid
                       }}] AS path_nodes,
                       [r IN relationships(shortest.path) | type(r)] AS path_rels,
                       shortest.len AS path_length
            '''
            result_target_type = 'Tier 0'

        try:
            results = conn.query(query, {'batch_sids': batch_sids},
                                 name=f"cross_domain_user_paths_{target_type}")
            return self._process_results(results, target_type=result_target_type)
        except Exception as e:
            if self.deps.diagnostics:
                self.deps.diagnostics.record_error(
                    f"cross_domain:user_paths.batch_{target_type}", e)
            return []

    def _process_results(self, results, target_type='Unknown'):
        findings = []

        for row in results:
            path_nodes = row.get('path_nodes') or []
            path_rels = row.get('path_rels') or []

            full_path = []
            for i, node in enumerate(path_nodes):
                full_path.append(node)
                if i < len(path_rels):
                    full_path.append(path_rels[i])

            findings.append({
                'source_user': row.get('source_user') or '',
                'source_domain': (row.get('source_domain') or '').upper(),
                'source_sid': row.get('source_sid'),
                'target_name': row.get('target_name') or '',
                'target_domain': (row.get('target_domain') or '').upper(),
                'target_type': target_type,
                'fullPath': full_path,
                'path_length': row.get('path_length') or 0,
            })

        return findings

    @classmethod
    def to_display_results(cls, findings, source_domain=None):
        if source_domain:
            source_domain_upper = source_domain.upper()
            findings = [f for f in findings if (f.get('source_domain') or '').upper() == source_domain_upper]

        if not findings:
            return {}

        path_to_users = defaultdict(set)

        for f in findings:
            full_path = f.get('fullPath') or []
            if not full_path:
                continue

            normalized = cls._normalize_path(full_path)
            if normalized:
                source_user = f.get('source_user') or ''
                user_display = source_user.split('@')[0] if '@' in source_user else source_user
                path_to_users[normalized].add(user_display)

        if not path_to_users:
            return {}

        sorted_paths = sorted(path_to_users.items(), key=lambda x: len(x[1]), reverse=True)

        results = {}
        for normalized_path, users in sorted_paths:
            sorted_users = sorted(users, key=str.lower)
            users_str = ", ".join(sorted_users)
            key = f"Users with Shared Path ({len(users)}): {users_str}"
            results[key] = f"Cross-Domain Path: {normalized_path}"

        total_users = len(set(u for users in path_to_users.values() for u in users))
        results['__total_user_count__'] = total_users

        return results

    @classmethod
    def _normalize_path(cls, full_path):
        if not full_path:
            return None

        parts = []
        for i, item in enumerate(full_path):
            if i % 2 == 0:  # Node
                if isinstance(item, dict):
                    name = item.get('name') or item.get('objectid') or 'Unknown'
                    domain = item.get('domain') or ''
                    labels = item.get('labels') or []
                    node_type = cls._extract_type(labels)

                    if '@' in name:
                        base_name = name.split('@')[0]
                        domain_part = name.split('@')[1] if '@' in name else domain
                        parts.append(f"{base_name} ({node_type}) [{domain_part}]")
                    elif domain:
                        parts.append(f"{name} ({node_type}) [{domain}]")
                    else:
                        parts.append(f"{name} ({node_type})")
                elif isinstance(item, str):
                    parts.append(f"{item} (Unknown)")
            else:  # Relationship
                parts.append(str(item))

        return " -> ".join(parts[1:]) if len(parts) > 1 else None

    @classmethod
    def _extract_type(cls, labels):
        for label in ['User', 'Computer', 'Group', 'GPO', 'OU', 'Domain', 'Container']:
            if label in labels:
                return label
        return 'Unknown'
