import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from .node_type_cache import AD_REPORT_LABELS


class EscalationPathsMixin:

    def get_user_escalation_paths(self, username=None, force_refresh=False, batch_mode=False, usernames=None):
        if batch_mode:
            return self._batch_process_escalation_paths(usernames, force_refresh)

        if not username:
            return []

        if not force_refresh:
            cached_paths, was_processed = self._get_cached_escalation_paths(username)
            if was_processed:
                return cached_paths

        bh_version = self.check_bh_version()

        if bh_version == "v2":
            results = self._get_escalation_paths_v2(username)
        else:
            results = self._get_escalation_paths_v1(username)

        if not hasattr(self, 'has_escalation_path_results_cache'):
            self.has_escalation_path_results_cache = {}

        has_paths = any(r.get('hasEscalationPath', False) for r in results) if results else False

        if has_paths:
            self.escalation_paths_cache[username] = results
            self.has_escalation_path_results_cache[username] = True

            for result in results:
                sid = result.get('sid')
                if sid and sid != username:
                    self.escalation_paths_cache[sid] = results
                    self.has_escalation_path_results_cache[sid] = True
        else:
            self.has_escalation_path_results_cache[username] = False

        return results

    def _batch_process_escalation_paths(self, usernames, force_refresh=False):
        if not usernames:
            return {}

        print(f"\n===== BATCH PROCESSING STARTED: {len(usernames)} objects =====", flush=True)
        start_time = time.time()

        sids = [u for u in usernames if isinstance(u, str) and u.startswith('S-1-')]
        names = [u for u in usernames if u not in sids]
        print(f"Processing {len(sids)} SIDs and {len(names)} usernames", flush=True)

        escalation_cache = self.escalation_paths_cache
        result_dict = {}
        cached_count = 0

        for entity in usernames:
            if entity in escalation_cache and not force_refresh:
                result_dict[entity] = escalation_cache[entity]
                cached_count += 1

        print(f"Using {cached_count} cached results, need to query {len(usernames) - cached_count} objects", flush=True)

        to_process = [u for u in usernames if u not in result_dict]
        if not to_process:
            print("No objects to process - all in cache", flush=True)
            return result_dict

        bh_version = self.check_bh_version()

        if bh_version == "v2":
            batch_results = self._batch_process_v2(to_process)
        else:
            batch_results = self._batch_process_v1(to_process)

        result_dict.update(batch_results)

        elapsed_time = time.time() - start_time
        print(f"===== BATCH PROCESSING COMPLETED in {elapsed_time:.2f}s =====", flush=True)

        return result_dict

    def _batch_process_v2(self, entities):
        result_dict = {}

        batch_size = 250 if len(entities) > 1000 else 200

        total_batches = (len(entities) + batch_size - 1) // batch_size

        print(f"Processing in {total_batches} batches of {batch_size} objects each", flush=True)

        if not hasattr(self, 'has_escalation_path_results_cache'):
            self.has_escalation_path_results_cache = {}

        escalation_cache = self.escalation_paths_cache
        has_escalation_cache = self.has_escalation_path_results_cache

        use_parallel = total_batches > 1

        if len(entities) > 10000:
            base_workers = 8
        elif len(entities) > 5000:
            base_workers = 8
        elif len(entities) > 2000:
            base_workers = 6
        elif len(entities) > 1000:
            base_workers = 4
        else:
            base_workers = 2

        max_workers = min(base_workers, total_batches, 10)

        if self._diagnostics:
            domain = self.get_domain_name()
            self._diagnostics.escalation_batches[domain] = {
                "mode": "parallel" if use_parallel else "sequential",
                "batch_size": batch_size,
                "total_batches": total_batches,
                "max_workers": max_workers if use_parallel else None,
                "batches": [],
            }

        # pre-warm cache so parallel workers don't race on first lookup
        self.get_all_relationships(exclude_mssql=True)

        if use_parallel:
            print(f"Using parallel processing with {max_workers} workers", flush=True)
            self._process_batches_parallel(entities, batch_size, result_dict, escalation_cache, has_escalation_cache, max_workers)
        else:
            self._process_batches_sequential(entities, batch_size, result_dict, escalation_cache, has_escalation_cache)


        total_with_paths = sum(1 for entity_results in result_dict.values() for result in entity_results if result.get('hasEscalationPath', False))
        print(f"Total entities with escalation paths: {total_with_paths}", flush=True)
        return result_dict

    def _extract_sample_path_display(self, full_path):
        if isinstance(full_path[0], dict):
            start_node = full_path[0].get('name') or 'Unknown'
        else:
            start_node = str(full_path[0])
        if '@' in start_node and '(' not in start_node.split('@')[1]:
            start_node = start_node.split('@')[0]

        end_idx = -2 if len(full_path) % 2 == 0 else -1
        if isinstance(full_path[end_idx], dict):
            end_node = full_path[end_idx].get('name') or 'Unknown'
        else:
            end_node = str(full_path[end_idx])
        if '@' in end_node and '(' not in end_node.split('@')[1]:
            end_node = end_node.split('@')[0]

        return start_node, end_node

    def _process_batches_sequential(self, entities, batch_size, result_dict, escalation_cache, has_escalation_cache):
        total_batches = (len(entities) + batch_size - 1) // batch_size

        for batch_num in range(total_batches):
            batch_start = batch_num * batch_size
            batch_end = min(batch_start + batch_size, len(entities))
            current_batch = entities[batch_start:batch_end]

            batch_start_time = time.time()

            try:
                batch_results = self._find_escalation_paths_v2(current_batch, interesting_rels_only=False, raise_on_error=True)
            except Exception as e:
                batch_time = time.time() - batch_start_time
                print(f"[BATCH {batch_num+1}/{total_batches}] FAILED ({batch_time:.2f}s): {e}", flush=True)
                if self._diagnostics:
                    domain = self.get_domain_name()
                    self._diagnostics.record_error(
                        f"escalation_batch_{batch_num}", e, domain=domain)
                    self._diagnostics.record_escalation_batch(
                        domain=domain,
                        batch_num=batch_num,
                        size=len(current_batch),
                        duration_ms=batch_time * 1000,
                        paths_found=0,
                        success=False,
                        error=e,
                    )
                continue

            if batch_results:
                count = 0
                for entity, paths in batch_results.items():
                    if count >= 5:
                        break

                    if not paths:
                        continue

                    for path_result in paths:
                        if path_result.get('hasEscalationPath', False):
                            full_path = path_result.get('fullPath', [])
                            if full_path and len(full_path) >= 3:
                                start_node, end_node = self._extract_sample_path_display(full_path)
                                print(f"  {count + 1}. {start_node} -> {end_node}")
                                count += 1
                                break

            for entity in current_batch:
                if entity in batch_results:
                    paths = batch_results[entity]
                    result_dict[entity] = paths
                    has_escalation_cache[entity] = True

                    if entity.startswith('S-1-'):
                        escalation_cache[entity] = paths

                    cached_sids = set()
                    for path_result in paths:
                        sid = path_result.get('sid')
                        if sid and sid != entity and sid not in cached_sids:
                            escalation_cache[sid] = paths
                            has_escalation_cache[sid] = True
                            cached_sids.add(sid)
                            break
                else:
                    result_dict[entity] = [{
                        'username': entity,
                        'enabled': True,
                        'isAdmin': False,
                        'hasEscalationPath': False,
                        'sid': entity if entity.startswith('S-1-') else None,
                        'fullPath': []
                    }]
                    has_escalation_cache[entity] = False

            batch_with_paths = sum(1 for entity in current_batch
                                if entity in batch_results and
                                any(p.get('hasEscalationPath', False) for p in batch_results.get(entity, [])))

            batch_time = time.time() - batch_start_time
            print(f"[BATCH {batch_num+1}/{total_batches}] Completed processing {len(current_batch)} objects ({batch_time:.2f}s) - {batch_with_paths} with paths", flush=True)

            if self._diagnostics:
                self._diagnostics.record_escalation_batch(
                    domain=self.get_domain_name(),
                    batch_num=batch_num,
                    size=len(current_batch),
                    duration_ms=batch_time * 1000,
                    paths_found=batch_with_paths,
                )

    def _process_batches_parallel(self, entities, batch_size, result_dict, escalation_cache, has_escalation_cache, max_workers):
        total_batches = (len(entities) + batch_size - 1) // batch_size

        batches = []
        for batch_num in range(total_batches):
            batch_start = batch_num * batch_size
            batch_end = min(batch_start + batch_size, len(entities))
            current_batch = entities[batch_start:batch_end]
            batches.append((batch_num, current_batch))

        worker_connections = []
        try:
            for i in range(max_workers):
                worker_connections.append(self.conn.get_connection_for_thread())

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_batch = {}
                for idx, (batch_num, batch) in enumerate(batches):
                    conn_idx = idx % max_workers
                    thread_conn = worker_connections[conn_idx]
                    future = executor.submit(self._process_batch_parallel, batch, thread_conn)
                    future_to_batch[future] = (batch_num, batch)

                for future in as_completed(future_to_batch):
                    batch_num, batch = future_to_batch[future]

                    batch_results, processing_time, batch_error = future.result()

                    if batch_error is not None:
                        print(f"[BATCH {batch_num}/{len(batches)}] FAILED ({processing_time:.2f}s): {batch_error}", flush=True)
                        if self._diagnostics:
                            domain = self.get_domain_name()
                            self._diagnostics.record_error(
                                f"escalation_batch_{batch_num}", batch_error, domain=domain)
                            self._diagnostics.record_escalation_batch(
                                domain=domain,
                                batch_num=batch_num,
                                size=len(batch),
                                duration_ms=processing_time * 1000,
                                paths_found=0,
                                success=False,
                                error=batch_error,
                            )
                        continue

                    batch_with_paths = sum(1 for entity in batch
                                        if entity in batch_results and
                                        any(p.get('hasEscalationPath', False) for p in batch_results.get(entity, [])))

                    print(f"[BATCH {batch_num}/{len(batches)}] Completed processing {len(batch)} objects ({processing_time:.2f}s) - {batch_with_paths} with paths", flush=True)

                    if self._diagnostics:
                        self._diagnostics.record_escalation_batch(
                            domain=self.get_domain_name(),
                            batch_num=batch_num,
                            size=len(batch),
                            duration_ms=processing_time * 1000,
                            paths_found=batch_with_paths,
                        )

                    if batch_results:
                        count = 0
                        for entity, paths in batch_results.items():
                            if count >= 5:
                                break

                            if not paths:
                                continue

                            for path_result in paths:
                                if path_result.get('hasEscalationPath', False):
                                    full_path = path_result.get('fullPath', [])
                                    if full_path and len(full_path) >= 3:
                                        start_node, end_node = self._extract_sample_path_display(full_path)
                                        print(f"  {count + 1}. {start_node} -> {end_node}")
                                        count += 1
                                        break

                    for entity in batch:
                        if entity in batch_results:
                            paths = batch_results[entity]
                            result_dict[entity] = paths
                            has_escalation_cache[entity] = True

                            if entity.startswith('S-1-'):
                                escalation_cache[entity] = paths

                            cached_sids = set()
                            for path_result in paths:
                                sid = path_result.get('sid')
                                if sid and sid != entity and sid not in cached_sids:
                                    escalation_cache[sid] = paths
                                    has_escalation_cache[sid] = True
                                    cached_sids.add(sid)
                                    break
                        else:
                            result_dict[entity] = [{
                                'username': entity,
                                'enabled': True,
                                'isAdmin': False,
                                'hasEscalationPath': False,
                                'sid': entity if entity.startswith('S-1-') else None,
                                'fullPath': []
                            }]
                            has_escalation_cache[entity] = False

        finally:
            for conn in worker_connections:
                try:
                    self.conn.return_connection_to_pool(conn)
                except:
                    pass

    def _find_escalation_paths_v2(self, entities, interesting_rels_only=False, conn=None, raise_on_error=False):
        if conn is None:
            conn = self.conn

        results = {}

        if interesting_rels_only:
            all_rels = self.get_interesting_relationships()
        else:
            # MSSQL has its own checks
            all_rels = self.get_all_relationships(exclude_mssql=True)

        if not all_rels:
            return {e: [{'username': e, 'enabled': True, 'isAdmin': False,
                         'hasEscalationPath': False, 'fullPath': []}] for e in entities}

        tier0_targets = ['DOMAIN ADMINS', 'DOMAIN CONTROLLERS', 'ENTERPRISE ADMINS', 'ADMINISTRATORS']

        try:
            detail_query = """
                MATCH (m)
                WHERE m.objectid IN $entities
                WITH m
                // Find high-value targets in the SAME domain (cross-domain paths handled separately)
                MATCH (g)
                WHERE (
                    g.highvalue = true OR
                    (g.system_tags IS NOT NULL AND g.system_tags CONTAINS 'admin_tier_0')
                )
                AND g <> m
                AND g.domain = m.domain
                """ + self._get_tier0_target_exclusion('g') + """
                // For each entity-target pair, find shortest path with max 6 hops
                WITH m, g
                MATCH p=shortestPath((m)-[:""" + all_rels + """*1..6]->(g))
                // Prefer paths to DA/DC/EA/Admin targets over other high-value targets
                WITH m.objectid AS entity_id, m, p, length(p) AS path_length,
                     CASE
                         WHEN any(lbl IN labels(last(nodes(p))) WHERE lbl IN ['User', 'Computer']) THEN 0
                         WHEN 'Group' IN labels(last(nodes(p))) AND any(name IN $tier0_targets WHERE last(nodes(p)).name CONTAINS name) THEN 0
                         ELSE 1
                     END AS target_priority
                ORDER BY entity_id, target_priority, path_length
                // Take the best path for each entity
                WITH entity_id, m, head(collect(p)) AS shortest_path
                WHERE shortest_path IS NOT NULL
                // Return full node details including SIDs
                RETURN
                    entity_id,
                    m.name AS username,
                    m.enabled AS enabled,
                    true AS hasEscalationPath,
                    [n in nodes(shortest_path) | {
                        name: n.name,
                        objectid: n.objectid,
                        guid: n.guid,
                        dn: n.distinguishedname,
                        labels: [
                            label IN labels(n)
                            WHERE label IN $report_labels
                        ],
                        samaccountname: n.samaccountname,
                        enabled: n.enabled,
                        domain: n.domain,
                        operatingsystem: n.operatingsystem,
                        functionallevel: n.functionallevel,
                        description: n.description,
                        caname: n.caname,
                        certname: n.certname,
                        dnshostname: n.dnshostname,
                        displayname: n.displayname
                    }] AS path_nodes,
                    [n in nodes(shortest_path) | CASE
                        WHEN 'User' IN labels(n) THEN 'User'
                        WHEN 'Computer' IN labels(n) THEN 'Computer'
                        WHEN 'Group' IN labels(n) THEN 'Group'
                        WHEN 'Domain' IN labels(n) THEN 'Domain'
                        WHEN 'GPO' IN labels(n) THEN 'GPO'
                        WHEN 'OU' IN labels(n) THEN 'OU'
                        WHEN 'Container' IN labels(n) THEN 'Container'
                        WHEN 'CertificateTemplate' IN labels(n) THEN 'CertTemplate'
                        WHEN 'Base' IN labels(n) AND n.distinguishedname =~ ".*CN=CERTIFICATE TEMPLATES.*" THEN 'CertTemplate'
                        ELSE 'Unknown'
                    END] AS path_node_types,
                    [r in relationships(shortest_path) | type(r)] AS relationship_types,
                    m.objectid AS sid,
                    length(shortest_path) AS path_length
                """
            query_params = {
                'entities': entities,
                'tier0_targets': tier0_targets,
                'report_labels': list(AD_REPORT_LABELS),
            }

            batch_results = conn.query(detail_query, parameters=query_params, name="find_escalation_paths")

            if batch_results:
                result_count = 0
                for result in batch_results:
                    result_count += 1
                    entity_id = result['entity_id']

                    path_nodes = result.get('path_nodes', [])
                    rel_types = result.get('relationship_types', [])

                    full_path = []
                    for i in range(len(path_nodes)):
                        node_obj = path_nodes[i]
                        full_path.append(node_obj)

                        if i < len(rel_types):
                            full_path.append(rel_types[i])

                    path_result = {
                        'entity_id': entity_id,
                        'username': result.get('username'),
                        'enabled': result.get('enabled'),
                        'isAdmin': self._is_admin_user(result.get('username', '')),
                        'hasEscalationPath': True,
                        'fullPath': full_path,
                        'sid': result.get('sid')
                    }

                    results[entity_id] = [path_result]

            else:
                pass

        except Exception:
            if raise_on_error:
                raise
            for entity in entities:
                results[entity] = [{
                    'username': entity,
                    'enabled': True,
                    'isAdmin': False,
                    'hasEscalationPath': False,
                    'fullPath': []
                }]
            return results

        entities_with_paths = set(results.keys())
        no_path_entities = [e for e in entities if e not in entities_with_paths]

        for entity in no_path_entities:
            results[entity] = [{
                'username': entity,
                'enabled': True,
                'isAdmin': False,
                'hasEscalationPath': False,
                'fullPath': []
            }]

        return results

    def _batch_process_v1(self, entities):
        result_dict = {}
        batch_size = 250
        total_batches = (len(entities) + batch_size - 1) // batch_size
        paths_found = 0

        print(f"Processing in {total_batches} batches of {batch_size} objects each (BloodHound v1)", flush=True)

        print("  Processing objects individually (BloodHound v1)...", flush=True)

        for i, entity in enumerate(entities):
            if (i+1) % 5 == 0 or i+1 == len(entities):
                progress = (i+1) / len(entities) * 100
                sys.stdout.write(f"\r  Progress: {i+1}/{len(entities)} ({progress:.1f}%)...")
                sys.stdout.flush()

            results = self._get_escalation_paths_v1(entity)

            if results:
                result_dict[entity] = results
                self.escalation_paths_cache[entity] = results

                if any(r.get('hasEscalationPath', False) for r in results):
                    paths_found += 1

                for result in results:
                    sid = result.get('sid')
                    if sid and sid != entity:
                        self.escalation_paths_cache[sid] = results
            else:
                result_dict[entity] = [{
                    'username': entity,
                    'enabled': True,
                    'isAdmin': False,
                    'hasEscalationPath': False,
                    'fullPath': []
                }]
                self.escalation_paths_cache[entity] = result_dict[entity]

        print(f"\n  Found {paths_found} objects with paths", flush=True)
        return result_dict

    @staticmethod
    def _escalation_target_priority(result):
        full_path = result.get('fullPath', [])
        if not full_path:
            return (1, 0)
        target = full_path[-1]
        if isinstance(target, dict):
            name = (target.get('name') or '').upper()
            labels = target.get('labels') or []
        else:
            # v1 paths are flat strings; no labels
            name = str(target).upper()
            labels = []
        tier0_groups = ['DOMAIN ADMINS', 'DOMAIN CONTROLLERS', 'ENTERPRISE ADMINS', 'ADMINISTRATORS']
        if 'User' in labels or 'Computer' in labels:
            return (0, len(full_path) // 2)
        if 'Group' in labels and any(g in name for g in tier0_groups):
            return (0, len(full_path) // 2)
        if not labels:
            if any(g in name for g in tier0_groups) or name.startswith('ADMINISTRATOR@'):
                return (0, len(full_path) // 2)
        return (1, len(full_path) // 2)

    def _get_escalation_paths_v1(self, entity):
        is_sid = entity.startswith('S-1-')
        query = f"""
            MATCH (m)
            WHERE {("m.objectid = $entity" if is_sid else "m.name = $entity")}
            WITH m
            OPTIONAL MATCH p=allShortestPaths((m)-[r*1..]->(n {{highvalue:true}}))
            WHERE NONE(r IN relationships(p) WHERE type(r) IN ["GetChanges", "GetChangesAll"])
            AND NOT m=n
            WITH m, p,
                CASE WHEN p IS NOT NULL THEN
                    reduce(s = [], i IN range(0, size(nodes(p)) - 2) |
                    s + [nodes(p)[i].name] + [type(relationships(p)[i])])
                ELSE []
                END AS interleavedPath
            RETURN DISTINCT
                toLower(m.name) AS username,
                m.enabled AS enabled,
                (p IS NOT NULL) AS hasEscalationPath,
                interleavedPath + CASE WHEN p IS NOT NULL THEN [last(nodes(p)).name] ELSE [] END AS fullPath,
                m.objectid AS sid
        """

        raw_results = self.conn.query(query, parameters={'entity': entity}, name="get_escalation_paths_v1")

        if not raw_results:
            return [{
                'username': entity,
                'enabled': True,
                'isAdmin': False,
                'hasEscalationPath': False,
                'fullPath': []
            }]

        results = [dict(r) for r in raw_results]
        for r in results:
            r['isAdmin'] = self._is_admin_user(r.get('username', ''))
        results = sorted(results, key=self._escalation_target_priority)
        return results

    def _get_escalation_paths_v2(self, entity):
        is_sid = entity.startswith('S-1-')

        where_condition = "m.objectid = $entity" if is_sid else "m.name = $entity"

        all_rels = self.get_all_relationships()
        if not all_rels:
            return [{'username': entity, 'enabled': True, 'isAdmin': False,
                     'hasEscalationPath': False, 'fullPath': []}]

        query = f"""
            MATCH (m)
            WHERE {where_condition}
            WITH m
            OPTIONAL MATCH p=allShortestPaths((m)-[:{all_rels}*1..6]->(g))
            WHERE g <> m AND (
                g.highvalue = true OR
                g.admincount = true OR
                (g.system_tags IS NOT NULL AND g.system_tags CONTAINS 'admin_tier_0') OR
                g.name =~ '.*DOMAIN ADMINS.*'
            )
            {self._get_tier0_target_exclusion('g')}
            WITH m, p,
                CASE
                    WHEN p IS NOT NULL THEN reduce(s = [], i IN range(0, size(nodes(p)) - 2) |
                        s + [
                            {{
                                name: nodes(p)[i].name,
                                objectid: nodes(p)[i].objectid,
                                guid: nodes(p)[i].guid,
                                dn: nodes(p)[i].distinguishedname,
                                labels: [
                                    label IN labels(nodes(p)[i])
                                    WHERE label IN $report_labels
                                ],
                                samaccountname: nodes(p)[i].samaccountname
                            }}
                        ] + [type(relationships(p)[i])]
                    )
                    ELSE []
                END AS interleavedPath
            RETURN DISTINCT
                toLower(m.name) AS username,
                m.enabled AS enabled,
                (p IS NOT NULL) AS hasEscalationPath,
                interleavedPath + CASE
                    WHEN p IS NOT NULL THEN [
                        {{
                            name: last(nodes(p)).name,
                            objectid: last(nodes(p)).objectid,
                            guid: last(nodes(p)).guid,
                            dn: last(nodes(p)).distinguishedname,
                            labels: [
                                label IN labels(last(nodes(p)))
                                WHERE label IN $report_labels
                            ],
                            samaccountname: last(nodes(p)).samaccountname
                        }}
                    ]
                    ELSE []
                END AS fullPath,
                m.objectid AS sid
        """

        raw_results = self.conn.query(
            query,
            parameters={
                'entity': entity,
                'report_labels': list(AD_REPORT_LABELS),
            },
            name="get_escalation_paths_v2",
        )

        if not raw_results:
            return [{
                'username': entity,
                'enabled': True,
                'isAdmin': False,
                'hasEscalationPath': False,
                'fullPath': []
            }]

        results = [dict(r) for r in raw_results]
        for r in results:
            r['isAdmin'] = self._is_admin_user(r.get('username', ''))
        results = sorted(results, key=self._escalation_target_priority)
        return results

    def get_user_escalation_paths_all_paths(self, username, force_refresh=False):
        bh_version = self.check_bh_version()

        if bh_version == "v1":
            return []

        cache_key = (username)
        if cache_key in self.escalation_paths_cache and not force_refresh:
            return self.escalation_paths_cache[cache_key]

        all_rels = self.get_all_relationships()
        if not all_rels:
            self.escalation_paths_cache[cache_key] = []
            return []

        query = f"""
            MATCH (m)
            WHERE (m:User OR m:Computer) AND m.name = $username
            WITH m
            MATCH p=(m)-[:{all_rels}*1..6]->(g)
            WHERE m <> g AND "admin_tier_0" IN split(g.system_tags, ' ')
            {self._get_tier0_target_exclusion('g')}
            WITH m, p,
                CASE
                    WHEN p IS NOT NULL THEN reduce(s = [], i IN range(0, size(nodes(p)) - 2) |
                        s + [nodes(p)[i].name] + [type(relationships(p)[i])])
                ELSE []
                END AS interleavedPath
            RETURN DISTINCT
                toLower(m.name) AS username,
                m.enabled AS enabled,
                (p IS NOT NULL) AS hasEscalationPath,
                interleavedPath + CASE WHEN p IS NOT NULL THEN [last(nodes(p)).name] ELSE [] END AS fullPath
        """

        raw_results = self.conn.query(query, parameters={'username': username.upper()}, name="get_user_escalation_paths_all")
        results = [dict(r) for r in raw_results] if raw_results else []
        for r in results:
            r['isAdmin'] = self._is_admin_user(r.get('username', ''))
        self.escalation_paths_cache[cache_key] = results
        return results

    def _get_cached_escalation_paths(self, entity_id):
        escalation_cache = getattr(self, 'has_escalation_path_results_cache', {})

        if entity_id in escalation_cache:
            has_paths = escalation_cache[entity_id]

            if has_paths:
                paths_cache = getattr(self, 'escalation_paths_cache', {})
                cached_paths = paths_cache.get(entity_id, [])
                return cached_paths, True
            else:
                empty_result = [{
                    'username': entity_id,
                    'enabled': True,
                    'isAdmin': False,
                    'hasEscalationPath': False,
                    'fullPath': []
                }]
                return empty_result, True

        return None, False

    def _process_batch_parallel(self, batch, thread_conn):
        start_time = time.time()

        try:
            batch_results = self._find_escalation_paths_v2(batch, interesting_rels_only=False, conn=thread_conn, raise_on_error=True)
            return batch_results, time.time() - start_time, None
        except Exception as e:
            return None, time.time() - start_time, e
