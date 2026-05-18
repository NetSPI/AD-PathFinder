from .hv_groups import ADMIN_GROUPS_LOWER


class AccountEscalationMixin:

    def check_escalation_path(self, all_user_data=None, user_escalation_paths=None,
                     return_all_paths=False, quiet=False, force_refresh=False):
        if all_user_data is None:
            all_user_data = self.get_all_user_data()

        if user_escalation_paths is None:
            user_escalation_paths = self._escalation_paths_cache

        if not force_refresh:
            cache_size = len(self._escalation_results_cache)
            if cache_size > 0:
                return self._escalation_results_cache

        if not quiet: print("Preparing entities for escalation path checking...")

        if not self._cached_domain_name:
            self._cached_domain_name = self.neo4j_data.get_domain_name()

        high_value_groups = ADMIN_GROUPS_LOWER

        for user in all_user_data:
            if user and user.get('username'):
                username = (user.get('username') or '').lower()
                sid = user.get('sid')
                if sid:
                    self.sid_to_username[sid] = username
                    self.username_to_sid[username] = sid

        has_escalation_path_results = {}
        sids_to_check = []
        for user_dict in all_user_data:
            if not user_dict:
                continue

            username = user_dict.get('username', '')
            sid = user_dict.get('sid')

            if not username or not sid:
                continue

            if not user_dict.get('enabled', True):
                continue

            if user_dict.get('is_domain_controller', False):
                continue

            if user_dict.get('isAdmin', False):
                continue

            username_upper = username.upper()
            if username_upper.startswith('ADMIN') or username_upper.startswith('MSOL'):
                continue
            user_groups = user_dict.get('groups', [])
            is_high_value = False

            for group in user_groups:
                group_lower = group.lower()
                for hv_group in high_value_groups:
                    if hv_group in group_lower:
                        is_high_value = True
                        break
                if is_high_value:
                    break

            if is_high_value:
                continue

            if sid in self._escalation_results_cache:
                has_escalation_path_results[sid] = self._escalation_results_cache[sid]
                continue

            if sid in user_escalation_paths:
                has_escalation_path_results[sid] = True
                continue

            sids_to_check.append((sid, user_dict))

        if len(sids_to_check) == 0:
            return has_escalation_path_results

        if not quiet: print(f"Checking escalation paths for {len(sids_to_check)} entities by SID...")
        sids_to_check_list = [sid for sid, _ in sids_to_check]

        sid_paths = self.neo4j_data.get_user_escalation_paths(None, force_refresh=False, batch_mode=True, usernames=sids_to_check_list)


        self._process_escalation_results(sids_to_check, sid_paths, user_escalation_paths,
                                       has_escalation_path_results, return_all_paths)

        if self._diagnostics and self._cached_domain_name not in self._diagnostics.escalation_paths:
            self._record_escalation_diagnostics(user_escalation_paths)

        if not quiet: print("Escalation path checking complete")

        self._escalation_results_cache = has_escalation_path_results

        return has_escalation_path_results

    def _process_escalation_results(self, sids_to_check, sid_paths, user_escalation_paths,
                                   has_escalation_path_results, return_all_paths):
        for sid, user_dict in sids_to_check:
            username = user_dict.get('username', '')
            results = sid_paths.get(sid)

            if results:
                has_path = any(res.get('hasEscalationPath', False) for res in results)
                if has_path:
                    valid_results = [res for res in results if res.get('hasEscalationPath') and res.get('fullPath')]
                    if valid_results:
                        if return_all_paths:
                            user_escalation_paths[sid] = [dict(res) for res in valid_results]
                            if username:
                                user_escalation_paths[username] = [dict(res) for res in valid_results]
                        else:
                            shortest_result = self._find_shortest_path_result(valid_results)
                            if shortest_result:
                                user_escalation_paths[sid] = [dict(shortest_result)]
                                if username:
                                    user_escalation_paths[username] = [dict(shortest_result)]
            else:
                user_escalation_paths[sid] = []
                if username:
                    user_escalation_paths[username] = []

            has_escalation_path_results[sid] = bool(results and any(res.get('hasEscalationPath', False) for res in results))
            if username:
                has_escalation_path_results[username] = has_escalation_path_results[sid]

    def _find_shortest_path_result(self, valid_results):
        if not valid_results:
            return None

        def path_length(result):
            path = result.get('fullPath')
            return len(path) if isinstance(path, list) else float('inf')

        valid_paths_lists = [r.get('fullPath') for r in valid_results]
        shortest_path = min(valid_paths_lists, key=lambda p: len(p) if isinstance(p, list) else float('inf'))
        shortest_length = len(shortest_path) if isinstance(shortest_path, list) else float('inf')
        for res in valid_results:
            if path_length(res) == shortest_length:
                return res

        return None

    def _record_escalation_diagnostics(self, user_escalation_paths):
        paths_with_data = {sid: p for sid, p in user_escalation_paths.items()
                          if p and not isinstance(sid, str) or (isinstance(sid, str) and sid.startswith('S-1-5-'))}
        all_paths = []
        for sid, path_list in paths_with_data.items():
            all_paths.extend(path_list)

        edge_counts = {}
        path_lengths = []
        for p in all_paths:
            full_path = p.get('fullPath', [])
            if isinstance(full_path, list) and full_path:
                edge_count = (len(full_path) - 1) // 2 if len(full_path) > 1 else 0
                path_lengths.append(edge_count)
                for elem in full_path:
                    if isinstance(elem, str):
                        edge_counts[elem] = edge_counts.get(elem, 0) + 1

        self._diagnostics.escalation_paths[self._cached_domain_name] = {
            "total_paths_computed": len(all_paths),
            "unique_sids_with_paths": len(paths_with_data),
            "average_path_length": round(sum(path_lengths) / len(path_lengths), 1) if path_lengths else 0,
            "longest_path": max(path_lengths) if path_lengths else 0,
            "path_edge_distribution": edge_counts,
        }

    def normalise_path(self, path):
        if not path:
            return ""

        if isinstance(path, str):
            print(f"[normalise_path] WARNING: Received string path '{path}' - expected list")
            return ""

        if not isinstance(path, list):
            print(f"[normalise_path] ERROR: Unexpected path type {type(path)}")
            return ""

        if path and isinstance(path[0], dict) and 'fullPath' in path[0]:
            extracted_paths = [item.get('fullPath') for item in path if isinstance(item, dict) and item.get('fullPath')]
            if not extracted_paths:
                return ""
            path = min(extracted_paths, key=len)
            if not isinstance(path, list):
                print(f"[normalise_path] WARNING: fullPath contained {type(path)} instead of list")
                return ""

        path = [item for item in path if item is not None]
        if not path:
            return ""

        clean_path_parts = []

        for i, item in enumerate(path):
            if i % 2 == 0:
                if isinstance(item, dict):
                    name = item.get('name', '')

                    if not name:
                        continue

                    if '@' in name:
                        name = name.split('@')[0]
                    elif '.' in name and not name.startswith('.'):
                        parts = name.split('.')
                        if len(parts) > 2 and all(len(p) > 1 for p in parts[-2:]):
                            name = parts[0]

                    formatted = self.type_cache.format_path_node(item)
                    clean_path_parts.append(formatted)

                elif isinstance(item, str):
                    if ' (' in item and item.endswith(')'):
                        clean_path_parts.append(item)
                    else:
                        formatted = self.type_cache.format_path_node(item)
                        clean_path_parts.append(formatted)

            else:
                clean_path_parts.append(str(item))

        if len(clean_path_parts) > 1:
            return " -> ".join(clean_path_parts[1:])
        else:
            return ""

    def _format_escalation_path(self, target_escalation_path):
        formatted_path_parts = []

        for i, item in enumerate(target_escalation_path):
            if isinstance(item, dict):
                name = item.get('name') or item.get('objectid') or 'Unknown'
                if i % 2 == 0:
                    labels = item.get('labels') or []
                    item_type = self._get_object_type_from_labels(labels)
                    if item_type:
                        formatted_path_parts.append(f"{name} ({item_type})")
                    else:
                        formatted_path_parts.append(name)
                else:
                    formatted_path_parts.append(name)
            else:
                formatted_path_parts.append(str(item))

        return " -> ".join(formatted_path_parts)

    def _resolve_target_type(self, target, target_sid, enhanced_sid_lookup, enhanced_paths):
        if target_sid and target_sid in enhanced_sid_lookup:
            return enhanced_sid_lookup[target_sid].get('targetType', '')

        node_type = self.type_cache.get_node_type(target_sid) if target_sid else self.type_cache.get_node_type(target)
        if node_type != 'Unknown':
            return node_type

        for ep in enhanced_paths:
            if ep.get('targetName') == target:
                return ep.get('targetType', '')

        return ''

    def _get_final_target_info(self, target_escalation_path):
        final_target = target_escalation_path[-1] if target_escalation_path else "UNKNOWN"

        if isinstance(final_target, dict):
            name = (final_target.get('name') or final_target.get('objectid') or 'UNKNOWN').upper()
            labels = final_target.get('labels') or []
            target_type = self._get_object_type_from_labels(labels)
            return {'name': name, 'type': target_type}
        else:
            name = str(final_target).strip("'[]").upper()
            return {'name': name, 'type': ''}
