from datetime import datetime
from collections import defaultdict


_RISK_CATEGORY_DESCRIPTIONS = {
    "Kerberoastable with Admin privileges and Weak Password":
        "User is an admin with a weak password and has a Service Principal Name (SPN) set, making it vulnerable to Kerberoasting attacks",
    "Non-admin Kerberoastable with Weak Password":
        "User has a weak password and has a Service Principal Name (SPN) set, making it vulnerable to Kerberoasting attacks",
    "AS-REP Roastable with Admin privileges and Weak Password":
        "User is an admin with a weak password and does not require Kerberos pre-authentication, making it vulnerable to AS-REP Roasting attacks",
    "Non-admin AS-REP Roastable with Weak Password":
        "User has a weak password and does not require Kerberos pre-authentication, making it vulnerable to AS-REP Roasting attacks",
    "User with Weak Password and Unconstrained Delegation":
        "User has a weak password and is configured for unconstrained delegation, which poses a significant security risk",
    "User with Weak Password and Constrained Delegation":
        "User has a weak password and is configured for constrained delegation, which can be abused if compromised",
    "Account with Shared Password":
        "This account shares its password with other accounts, making it difficult to track individual user actions",
}

_PASSWORD_CATEGORY_DESCRIPTIONS = {
    "blank password": "User has a blank password",
    "username similarity": "User's password contains or is similar to their username",
    "lm hash configured": "User's account is configured to store the insecure LM hash",
    "password": "User's password is considered weak due to containing a variation of the word password",
    "welcome": "User's password is considered weak due to containing a variation of the word welcome",
    "season of the year": "User's password is considered weak due to containing a season-of-the-year",
    "day of week": "User's password is considered weak due to containing a day-of-the-week",
    "month of year": "User's password is considered weak due to containing a month-of-the-year",
    "company name": "User's password is considered weak due to containing the company name",
}

_BLANK_NTLM_HASH = "31D6CFE0D16AE931B73C59D7E0C089C0"


def _password_fallback_category(password, entity_name):
    if password == "" or password == _BLANK_NTLM_HASH:
        return "blank password"
    if entity_name.lower() in password.lower() or password.lower().startswith(entity_name.lower()):
        return "username similarity"
    return "weak password"


class ReportJsonMixin:
    def _normalize_sids_in_data(self, data):
        from .utils import normalize_sid

        if isinstance(data, dict):
            normalized_data = {}
            for key, value in data.items():
                if key in ['sid', 'Source Group SID', 'Target Object SID', 'targetSID', 'sourceSID'] and value:
                    normalized_data[key] = normalize_sid(value)
                else:
                    normalized_data[key] = self._normalize_sids_in_data(value)
            return normalized_data
        elif isinstance(data, list):
            return [self._normalize_sids_in_data(item) for item in data]
        else:
            return data

    def _generate_json_data(self, organised_risk_profiles, output_format):
        if not hasattr(self.account_analysis, 'ensure_user_details_populated'):
            return {}
        if not self.neo4j_data:
            return {}

        print("Generating JSON data...")

        self.account_analysis.ensure_user_details_populated()

        enabled_dc_fqdn = self._find_enabled_domain_controller()
        path_cache = getattr(self.account_analysis, '_escalation_paths_cache', {})

        path_categories = ["Non-admin Users with Escalation Paths", "Computers with Escalation Paths"]
        entity_details_cache = {}

        all_path_object_sids, unique_paths_data, identifier_to_path_key = self._collect_path_objects(
            organised_risk_profiles, path_cache, path_categories)

        path_relationship_map = self._build_relationship_context_map(unique_paths_data)

        sid_to_details_map = self._get_path_object_details(all_path_object_sids)

        processed_path_details = self._preprocess_path_details(unique_paths_data, sid_to_details_map,
                                                            path_relationship_map)

        entities_dict, domain_summary = self._build_entities_and_domain_summary(
            organised_risk_profiles, path_categories,
            identifier_to_path_key, processed_path_details, entity_details_cache,
            output_format, sid_to_details_map)

        self._enrich_entity_groups(entities_dict)
        destination_groups = self._enrich_destination_groups(entities_dict)
        self._enrich_enterprise_ca_status(entities_dict)

        password_statistics = self._gather_password_statistics()

        final_data = {
            "metadata": {
                "domain": self.domain_name,
                "domain_sid": self.domain_sid,
                "report_generated": datetime.now().isoformat(),
                "output_format": output_format,
                "unique_paths_count": len(unique_paths_data),
                "enabled_dc_fqdn": enabled_dc_fqdn
            },
            "entities": list(entities_dict.values()),
            "domain_summary": domain_summary,
            "destination_groups": destination_groups,
            "password_statistics": password_statistics
        }

        final_data = self._normalize_sids_in_data(final_data)

        return final_data

    def _enrich_entity_groups(self, entities_dict):
        try:
            risked_sids = [e.get('sid') for e in entities_dict.values() if e.get('sid')]
            if not risked_sids:
                return
            full_groups = self.neo4j_data.get_full_groups_for_sids(risked_sids)
            for entity in entities_dict.values():
                sid = entity.get('sid')
                if sid and sid in full_groups and full_groups[sid]:
                    entity['groups'] = full_groups[sid]
        except Exception as e:
            print(f"Warning: group enrichment failed: {e}")

    def _enrich_destination_groups(self, entities_dict):
        destination_groups = {}
        try:
            dest_sids = set()
            for entity in entities_dict.values():
                for risk in entity.get('risks', []):
                    spn = risk.get('details', {}).get('shortest_path_names', [])
                    if spn and isinstance(spn[-1], dict):
                        dest_sid = spn[-1].get('objectid')
                        dest_name = spn[-1].get('name', '')
                        if dest_sid and dest_name:
                            dest_sids.add(dest_sid)
            if not dest_sids:
                return destination_groups
            dest_groups_raw = self.neo4j_data.get_full_groups_for_sids(list(dest_sids))
            # Map by name to match how the client report looks up destinations
            for entity in entities_dict.values():
                for risk in entity.get('risks', []):
                    spn = risk.get('details', {}).get('shortest_path_names', [])
                    if spn and isinstance(spn[-1], dict):
                        dest = spn[-1]
                        sid = dest.get('objectid', '')
                        name = dest.get('name', '')
                        if sid in dest_groups_raw and name and name not in destination_groups:
                            destination_groups[name] = dest_groups_raw[sid]
        except Exception as e:
            print(f"Warning: destination group enrichment failed: {e}")
        return destination_groups

    def _enrich_enterprise_ca_status(self, entities_dict):
        try:
            ca_status = self.neo4j_data.get_enterprise_ca_status()
            if not ca_status:
                return
            for entity in entities_dict.values():
                for risk in entity.get('risks', []):
                    spn = risk.get('details', {}).get('shortest_path_names', [])
                    if spn and isinstance(spn[-1], dict):
                        dest = spn[-1]
                        sid = dest.get('objectid', '')
                        if sid in ca_status:
                            dest['ca_active'] = ca_status[sid]['active']
                            dest['ca_template_count'] = ca_status[sid]['template_count']
        except Exception as e:
            print(f"Warning: CA status enrichment failed: {e}")

    def _find_enabled_domain_controller(self):
        processed_dc_sids = set()
        
        for details in self.account_analysis.user_details_mapping.values():
            if isinstance(details, dict) and details.get('sid') and details.get('is_domain_controller') and details.get('enabled') and details.get('is_computer'):
                sid = details['sid']
                if sid not in processed_dc_sids:
                    processed_dc_sids.add(sid)
                    potential_fqdn = details.get('username_with_domain')
                    if potential_fqdn and '.' in potential_fqdn:
                        return potential_fqdn
        return None

    def _collect_path_objects(self, organised_risk_profiles, path_cache, path_categories):
        all_path_object_sids = set()
        unique_paths_data = {}
        identifier_to_path_key = {}

        self.current_path_object_details = {}

        for level, categories in organised_risk_profiles.items():
            for category, identifiers in categories.items():
                if category in ('Default Groups with Privilege Escalation Paths', 'Common Groups with Privilege Escalation Paths') and isinstance(identifiers, dict):
                    for group_type, paths in identifiers.items():
                        if paths and isinstance(paths, list):
                            for path in paths:
                                if isinstance(path, str) and ' -> ' in path:
                                    target = path.split(' -> ')[1].strip()
                                    if target:
                                        all_path_object_sids.add(target)
                    continue

                if category == 'Computers with WebClient and Escalation Paths' and isinstance(identifiers, dict):
                    computers_list = identifiers.get('Computers with WebClient and Escalation Paths', [])

                    if computers_list and isinstance(computers_list, list):
                        for idx, computer_path in enumerate(computers_list, 1):
                            if isinstance(computer_path, str) and ' -> ' in computer_path:
                                parts = computer_path.split(' -> ')
                                target = parts[-1].strip()
                                if target:
                                    all_path_object_sids.add(target)
                    continue

                if category not in path_categories or not isinstance(identifiers, dict):
                    continue

                for identifier in identifiers.keys():
                    path_data_list = path_cache.get(identifier)

                    if not path_data_list:
                        entity_details = self.account_analysis._get_entity_details(identifier)
                        if entity_details:
                            sid = entity_details.get('sid')
                            username_with_domain = (entity_details.get('username_with_domain') or '').upper()
                            if sid and sid in path_cache:
                                path_data_list = path_cache[sid]
                            elif username_with_domain in path_cache:
                                path_data_list = path_cache[username_with_domain]

                    if not path_data_list or not isinstance(path_data_list, list):
                        continue

                    for path_entry in path_data_list:
                        if isinstance(path_entry, dict) and path_entry.get('hasEscalationPath', False) and isinstance(path_entry.get('fullPath'), list) and path_entry.get('fullPath'):
                            path_names = path_entry['fullPath']
                            path_key = self.account_analysis.normalise_path(path_names)
                            if not path_key:
                                continue

                            identifier_to_path_key[identifier] = path_key
                            if path_key not in unique_paths_data:
                                unique_paths_data[path_key] = {'path': path_names, 'users': []}
                                for i, item in enumerate(path_names):
                                    if i % 2 == 0 and item:  # nodes are at even indices
                                        if isinstance(item, dict):
                                            object_id = item.get('objectid')
                                            if object_id:
                                                all_path_object_sids.add(object_id)

                                                self.current_path_object_details[object_id] = {
                                                    'name': item.get('name'),
                                                    'sid': object_id,
                                                    'guid': item.get('guid'),
                                                    'dn': item.get('dn'),
                                                    'type': self._determine_object_type_from_labels(item.get('labels', [])),
                                                    'samaccountname': item.get('samaccountname')
                                                }
                                            else:
                                                # dict format but no objectid — key by display name
                                                item_name = item.get('name')
                                                if item_name:
                                                    all_path_object_sids.add(item_name)
                                        else:
                                            # legacy v1 paths are flat strings
                                            item_str = str(item)
                                            all_path_object_sids.add(item_str)

                            unique_paths_data[path_key]['users'].append(identifier)
                            break  # Use the first valid path we find

        return all_path_object_sids, unique_paths_data, identifier_to_path_key
    
    def _determine_object_type_from_labels(self, labels):
        return self.type_cache._extract_type_from_labels(labels) if labels else None

    def _build_relationship_context_map(self, unique_paths_data):
        path_relationship_map = {}

        for path_key, data in unique_paths_data.items():
            path_list = data.get('path', [])
            for i in range(0, len(path_list) - 2, 2):
                source = str(path_list[i]).lower()
                relationship = str(path_list[i+1]).lower()
                target = str(path_list[i+2]).lower()

                if source not in path_relationship_map:
                    path_relationship_map[source] = {}
                if target not in path_relationship_map[source]:
                    path_relationship_map[source][target] = set()

                path_relationship_map[source][target].add(relationship)

        return path_relationship_map

    def _get_password_category(self, entity_name):
        if not hasattr(self.analysis, 'category_details'):
            return None

        blank_hash = "31D6CFE0D16AE931B73C59D7E0C089C0"
        cracked_accounts = getattr(self.account_analysis, 'cracked_accounts', {})
        password = cracked_accounts.get(entity_name.lower())
        
        if password == blank_hash or password == "":
            return "blank password"
        
        for category_name, category_data in self.analysis.category_details.items():
            for user_entry in category_data.get("users", []):
                # Entries are either "username:password" or just "username"
                user = user_entry.split(":")[0] if ":" in user_entry else user_entry
                if user.lower() == entity_name.lower():
                    return category_name

        return "weak password"

    def _get_path_object_details(self, all_path_object_sids):
        sid_to_details_map = {}

        if hasattr(self, 'current_path_object_details') and self.current_path_object_details:
            for object_sid, object_details in self.current_path_object_details.items():
                if not object_sid:
                    continue

                if object_sid not in sid_to_details_map:
                    sid_to_details_map[object_sid] = object_details

        missing_sids = []
        for sid_or_identifier in all_path_object_sids:
            if isinstance(sid_or_identifier, str) and sid_or_identifier.startswith('S-1-'):
                if sid_or_identifier not in sid_to_details_map:
                    missing_sids.append(sid_or_identifier)

        if missing_sids:
            try:
                object_details_list = self.neo4j_data.get_object_details_by_sids(missing_sids)

                for detail in object_details_list:
                    if not isinstance(detail, dict):
                        continue

                    sid_value = detail.get('sid')

                    # Only store by SID
                    if sid_value and sid_value.startswith('S-1-'):
                        sid_to_details_map[sid_value] = detail

            except Exception as e:
                print(f"Warning: Failed to fetch path object details: {e}")

        return sid_to_details_map
        
    def _preprocess_path_details(self, unique_paths_data, sid_to_details_map, path_relationship_map):
        processed_path_details = {}
        lookup_failure_sids = set()

        for path_key, data in unique_paths_data.items():
            original_full_path_list = data.get('path', [])
            current_path_object_details = {}
            processed_nodes_in_path = set()

            for i, item in enumerate(original_full_path_list):
                if i % 2 == 0:  # Only process nodes
                    if item is None:
                        continue

                    lookup_sid = None
                    item_name = None

                    if isinstance(item, dict):
                        lookup_sid = item.get('objectid')
                        item_name = item.get('name', str(lookup_sid) if lookup_sid else 'Unknown')

                        if not lookup_sid or not lookup_sid.startswith('S-1-'):
                            continue
                    else:
                        if isinstance(item, str) and item.startswith('S-1-'):
                            lookup_sid = item
                            item_name = item
                        else:
                            continue

                    if not lookup_sid or lookup_sid in processed_nodes_in_path:
                        continue

                    processed_nodes_in_path.add(lookup_sid)

                    if lookup_sid in sid_to_details_map:
                        looked_up_details = sid_to_details_map[lookup_sid]

                        current_path_object_details[item_name] = {
                            "dn": looked_up_details.get("dn"),
                            "type": looked_up_details.get("type", "Unknown"),
                            "sid": looked_up_details.get("sid"),
                            "resolution_method": "direct_sid"
                        }
                    elif lookup_sid not in lookup_failure_sids:
                        lookup_failure_sids.add(lookup_sid)

            processed_path_details[path_key] = {
                "original_full_path_list": original_full_path_list,
                "original_path_object_details": current_path_object_details if current_path_object_details else None
            }

        return processed_path_details

    def _build_entities_and_domain_summary(self, organised_risk_profiles, path_categories,
                                        identifier_to_path_key, processed_path_details, entity_details_cache,
                                        output_format, sid_to_details_map):
        entities_dict = {}
        temp_summary_collector = defaultdict(lambda: defaultdict(list))

        krbtgt_details_for_domain = self.account_analysis._get_entity_details('name:krbtgt')

        for level, categories in organised_risk_profiles.items():
            for category, identifiers_data in categories.items():
                if category == 'KRBTGT Password Older Than 6 Months':
                    if level in self.account_analysis.category_to_risk_level.values() and isinstance(identifiers_data, dict) and krbtgt_details_for_domain:
                        temp_summary_collector[level][category].append({
                            'identifier': 'krbtgt', 'entity_name': 'krbtgt', 'details': krbtgt_details_for_domain
                        })
                    continue
                elif category in ('Default Groups with Privilege Escalation Paths', 'Common Groups with Privilege Escalation Paths'):
                    if level in self.account_analysis.category_to_risk_level.values() and isinstance(identifiers_data, dict):
                        temp_summary_collector[level][category].append({'raw_group_paths': identifiers_data})
                    continue
                elif category == 'Computers with WebClient and Escalation Paths':
                    if level in self.account_analysis.category_to_risk_level.values() and isinstance(identifiers_data, dict):
                        temp_summary_collector[level][category].append({'raw_webclient_paths': identifiers_data})
                    continue

                if not isinstance(identifiers_data, dict) or not identifiers_data:
                    continue

                for identifier in identifiers_data.keys():
                    if identifier not in entity_details_cache:
                        entity_details = self.account_analysis._get_entity_details(identifier)
                        entity_details_cache[identifier] = entity_details
                    else:
                        entity_details = entity_details_cache[identifier]

                    if not entity_details: continue

                    entity_sid = entity_details.get('sid')
                    entity_key = entity_sid if entity_sid else identifier
                    entity_name = entity_details.get('username', identifier)
                    entity_type = entity_details.get('type', ('Computer' if str(entity_name).endswith('$') else 'User'))

                    if entity_key not in entities_dict:
                        entities_dict[entity_key] = {
                            "sid": entity_sid, "name": entity_name, "type": entity_type,
                            "enabled": entity_details.get('enabled', False),
                            "isAdmin": entity_details.get('isAdmin', False),
                            "isPrivileged": entity_details.get('isPrivileged', False),
                            "description": entity_details.get('description', 'No description available'),
                            "distinguishedname": entity_details.get('distinguishedname'),
                            "groups": entity_details.get('groups', []),
                            "lastLogon": entity_details.get('lastLogon'),
                            "passwordLastChanged": entity_details.get('passwordLastChanged'),
                            "risks": []
                        }
                    elif not entities_dict[entity_key].get('distinguishedname'):
                        current_dn = entity_details.get('distinguishedname')
                        if current_dn: entities_dict[entity_key]['distinguishedname'] = current_dn

                    risk_object = {"level": level, "category": category, "details": {}}

                    if category in path_categories and identifier in identifier_to_path_key:
                        self._add_path_details(identifier, identifier_to_path_key, processed_path_details,
                                            entity_details, risk_object)

                    if output_format == 'unsafe':
                        self._add_password_details(category, entity_name, risk_object)
                    if 'Delegation' in category:
                        self._add_delegation_details(category, entity_details, risk_object)

                    # Dict-shaped check results contribute their `details` to the risk object.
                    check_result = identifiers_data.get(identifier)
                    if isinstance(check_result, dict):
                        extra_details = check_result.get('details')
                        if isinstance(extra_details, dict):
                            risk_object["details"].update(extra_details)

                    if not risk_object["details"]: del risk_object["details"]
                    entities_dict[entity_key]["risks"].append(risk_object)
                    temp_summary_collector[level][category].append({
                        'identifier': identifier, 'entity_name': entity_name,
                        'details': entity_details, 'path_key': identifier_to_path_key.get(identifier)
                    })

        domain_summary = {'Critical': {}, 'High': {}, 'Medium': {}, 'Low': {}, 'Info': {}}

        for level, categories_data_from_temp in temp_summary_collector.items():
            if level not in domain_summary: continue

            for category, collected_entities_info in categories_data_from_temp.items():
                if not collected_entities_info: continue

                if category == "KRBTGT Password Older Than 6 Months":
                    self._process_krbtgt_password(level, category, krbtgt_details_for_domain, domain_summary)
                    continue
                elif category in ("Default Groups with Privilege Escalation Paths", "Common Groups with Privilege Escalation Paths"):
                    if collected_entities_info and isinstance(collected_entities_info[0], dict) and 'raw_group_paths' in collected_entities_info[0]:
                        raw_identifiers = collected_entities_info[0]['raw_group_paths']
                        self._process_default_groups(level, category, raw_identifiers, domain_summary, sid_to_details_map)
                    continue
                elif category == "Computers with WebClient and Escalation Paths":
                    if collected_entities_info and isinstance(collected_entities_info[0], dict) and 'raw_webclient_paths' in collected_entities_info[0]:
                        raw_identifiers = collected_entities_info[0]['raw_webclient_paths']
                        self._process_webclient_computers(level, category, raw_identifiers, domain_summary, sid_to_details_map)
                    continue

                summary_entry_content = {}
                if category in path_categories: # "Non-admin Users with Escalation Paths", "Computers with Escalation Paths"
                    path_groups = defaultdict(list)
                    for entity_info in collected_entities_info:
                        path_key = entity_info.get('path_key')
                        if path_key: path_groups[path_key].append(entity_info['entity_name'])

                    path_groups_list = [{"path_string": path_key, "count": len(names), "entities": sorted(names)}
                                        for path_key, names in path_groups.items() if names]
                    path_groups_list.sort(key=lambda x: x['count'], reverse=True)
                    if path_groups_list:
                        summary_entry_content["path_groups"] = path_groups_list

                if summary_entry_content:
                    if level not in domain_summary: domain_summary[level] = {}
                    domain_summary[level][category] = {
                        "total_count": len(collected_entities_info),
                        **summary_entry_content
                    }

        return entities_dict, domain_summary

    def _process_krbtgt_password(self, level, category, krbtgt_details, domain_summary):
        if level in domain_summary and krbtgt_details:
            last_changed_raw = krbtgt_details.get('passwordLastChanged')
            last_changed_formatted = "Unknown"

            if last_changed_raw and last_changed_raw not in ['Never', 'Unknown', None, 0, -1, -1.0, "0"]:
                try:
                    ts_float = float(last_changed_raw)
                    last_changed_dt = None

                    # Check if it's a Windows timestamp
                    if ts_float > 116444736000000000:
                        seconds_since_1601 = ts_float / 10_000_000
                        epoch_diff_seconds = (datetime(1970, 1, 1) - datetime(1601, 1, 1)).total_seconds()
                        unix_timestamp = seconds_since_1601 - epoch_diff_seconds
                        if unix_timestamp > 0:
                            last_changed_dt = datetime.fromtimestamp(unix_timestamp)
                    elif ts_float > 946684800:  # Plausible Unix timestamp
                        last_changed_dt = datetime.fromtimestamp(ts_float)

                    if last_changed_dt:
                        last_changed_formatted = last_changed_dt.strftime('%Y-%m-%d')
                except (ValueError, TypeError, OverflowError) as e:
                    last_changed_formatted = f"Error Parsing ({last_changed_raw}): {e}"

            if category not in domain_summary[level]:
                domain_summary[level][category] = {}

            domain_summary[level][category] = {
                "total_count": 1,
                "entities": ["krbtgt"],
                "details": {"last_changed_on": last_changed_formatted}
            }

    def _process_default_groups(self, level, category, identifiers, domain_summary_target, sid_to_details_map):
        if not isinstance(identifiers, dict) or not identifiers:
            return

        if level not in domain_summary_target:
            domain_summary_target[level] = {}

        enhanced_data = identifiers.get("___enhanced_data___", {})
        if not enhanced_data:
            enriched_group_details = {}
            for group_name, path_list in identifiers.items():
                if group_name == "___enhanced_data___":
                    continue

                if path_list and isinstance(path_list, list):
                    enriched_group_details[group_name] = {
                        "paths": sorted(path_list)
                    }

            if enriched_group_details:
                domain_summary_target[level][category] = {
                    "total_count": len(enriched_group_details),
                    "group_details": enriched_group_details
                }
            else:
                domain_summary_target[level][category] = {"total_count": 0}
            return

        enriched_group_details = {}

        for group_name, path_entries in enhanced_data.items():
            if not path_entries or not isinstance(path_entries, list):
                continue

            group_object_details = {}
            valid_paths_for_group = []

            for path_entry in path_entries:
                if not isinstance(path_entry, dict):
                    continue

                path_str = path_entry.get('fullPath')
                if not path_str:
                    continue

                valid_paths_for_group.append(path_str)

                target_name = path_entry.get('targetName')
                target_sid = path_entry.get('targetSID')

                if target_name and target_sid:
                    enhanced_details = None
                    if target_sid.startswith('S-1-') and target_sid in sid_to_details_map:
                        enhanced_details = sid_to_details_map[target_sid]

                    if enhanced_details:
                        group_object_details[target_name] = {
                            "type": enhanced_details.get('type', path_entry.get('targetType', 'Unknown_Entity')),
                            "sid": enhanced_details.get('sid', target_sid),
                            "dn": enhanced_details.get('dn', path_entry.get('targetDN', 'N/A'))
                        }
                    else:
                        # SID missed the lookup; use whatever the path entry has
                        group_object_details[target_name] = {
                            "type": path_entry.get('targetType', 'Unknown_Entity'),
                            "sid": target_sid,
                            "dn": path_entry.get('targetDN', 'N/A')
                        }

            if valid_paths_for_group:
                enriched_group_details[group_name] = {
                    "paths": sorted(valid_paths_for_group),
                    "path_object_details": group_object_details
                }

        if enriched_group_details:
            domain_summary_target[level][category] = {
                "total_count": len(enriched_group_details),
                "group_details": enriched_group_details
            }
        else:
            domain_summary_target[level][category] = {"total_count": 0}

    def _process_webclient_computers(self, level, category, identifiers, domain_summary_target, sid_to_details_map):
        
        if not isinstance(identifiers, dict) or not identifiers:
            return
        
        
        if level not in domain_summary_target: 
            domain_summary_target[level] = {}
        
        webclient_stats = identifiers.get("___webclient_stats___", {})
        computers_with_paths = identifiers.get("Computers with WebClient and Escalation Paths", [])
        
        
        webclient_computer_details = []
        
        for idx, computer_path_summary in enumerate(computers_with_paths, 1):
            if " -> " in computer_path_summary:
                parts = computer_path_summary.split(" -> ")
                computer_part = parts[0]
                
                if " (" in computer_part:
                    computer_name = computer_part.split(" (")[0]
                    os_info = computer_part.split(" (")[1].rstrip(")")
                else:
                    computer_name = computer_part
                    os_info = "Unknown OS"
                
                target = parts[-1] if len(parts) > 1 else "High Value Target"
                
                detail_entry = {
                    "computer_name": computer_name,
                    "operating_system": os_info,
                    "path_target": target,
                    "path_summary": computer_path_summary
                }
                webclient_computer_details.append(detail_entry)
        
        if webclient_computer_details:
            domain_summary_target[level][category] = {
                "total_count": len(webclient_computer_details),
                "total_webclient_computers": webclient_stats.get('total_with_webclient', len(webclient_computer_details)),
                "computer_details": webclient_computer_details
            }
        else:
            domain_summary_target[level][category] = {
                "total_count": 0,
                "total_webclient_computers": webclient_stats.get('total_with_webclient', 0)
            }
        

    def _add_path_details(self, identifier, identifier_to_path_key, processed_path_details,
                    entity_details, risk_object):
        path_key = identifier_to_path_key[identifier]
        path_details_were_added = False

        if path_key in processed_path_details:
            preprocessed_data = processed_path_details[path_key]
            original_full_path_list = preprocessed_data.get("original_full_path_list", [])
            original_path_object_details = preprocessed_data.get("original_path_object_details", {})
            current_entity_fqdn = entity_details.get('username_with_domain')

            if not original_full_path_list:
                return False

            final_path_list = original_full_path_list
            final_path_object_details = original_path_object_details

            # rewrite the first node so the rendered path starts on this entity
            if current_entity_fqdn and original_full_path_list:
                first_node_name = None
                if isinstance(original_full_path_list[0], dict) and 'name' in original_full_path_list[0]:
                    first_node_name = original_full_path_list[0]['name']
                else:
                    first_node_name = str(original_full_path_list[0]) if original_full_path_list[0] is not None else None

                if first_node_name and first_node_name.upper() != current_entity_fqdn.upper():
                    if len(original_full_path_list) >= 1:
                        corrected_first_node = {
                            'name': current_entity_fqdn,
                            'objectid': entity_details.get('sid'),
                            'dn': entity_details.get('distinguishedname'),
                            'labels': [entity_details.get('type', 'User' if not entity_details.get('is_computer', False) else 'Computer')]
                        }

                        corrected_path_list = [corrected_first_node] + original_full_path_list[1:]

                        filtered_object_details = {
                            current_entity_fqdn: {
                                "dn": entity_details.get("distinguishedname"),
                                "type": entity_details.get("type", "User" if not entity_details.get('is_computer', False) else "Computer"),
                                "sid": entity_details.get("sid")
                            }
                        }

                        processed_corrected_nodes = {current_entity_fqdn.lower()}
                        for i, node_item in enumerate(corrected_path_list):
                            if i % 2 == 0 and i != 0:
                                node_name = None
                                if isinstance(node_item, dict) and 'name' in node_item:
                                    node_name = node_item['name']
                                else:
                                    node_name = str(node_item) if node_item is not None else None

                                if node_name is not None:
                                    node_name_lower = node_name.lower()
                                    if node_name_lower not in processed_corrected_nodes:
                                        if original_path_object_details and node_name in original_path_object_details:
                                            filtered_object_details[node_name] = original_path_object_details[node_name]
                                        elif isinstance(node_item, dict):
                                            filtered_object_details[node_name] = {
                                                "dn": node_item.get('dn'),
                                                "type": self._determine_node_type_from_labels(node_item.get('labels', [])),
                                                "sid": node_item.get('objectid')
                                            }
                                        processed_corrected_nodes.add(node_name_lower)

                        final_path_list = corrected_path_list
                        final_path_object_details = filtered_object_details if filtered_object_details else None

            risk_object["details"]["shortest_path_names"] = final_path_list
            risk_object["details"]["path_object_details"] = final_path_object_details
            path_details_were_added = True

        return path_details_were_added
   
    def _determine_node_type_from_labels(self, labels):
        return self.type_cache._extract_type_from_labels(labels)


    def _add_password_details(self, category, entity_name, risk_object):
        weak_pwd_categories = [
            "Non-admin with Weak Password", "Admin with Weak Password",
            "Kerberoastable with Admin privileges and Weak Password",
            "AS-REP Roastable with Admin privileges and Weak Password",
            "Non-admin Kerberoastable with Weak Password",
            "Non-admin AS-REP Roastable with Weak Password",
            "User with Weak Password and Unconstrained Delegation",
            "User with Weak Password and Constrained Delegation"]

        if category not in weak_pwd_categories:
            return False

        cracked_accounts = getattr(self.account_analysis, 'cracked_accounts', {})
        password = cracked_accounts.get(entity_name.lower())
        if password is None:
            return False

        password_category = self._get_password_category(entity_name) or _password_fallback_category(password, entity_name)
        risk_object["details"]["password_category"] = password_category
        risk_object["details"]["risk_category"] = category
        risk_object["details"]["password_description"] = self._format_category_description(password_category, category)
        return True
    
    def _format_category_description(self, category, risk_category=None):
        if risk_category and risk_category in _RISK_CATEGORY_DESCRIPTIONS:
            return _RISK_CATEGORY_DESCRIPTIONS[risk_category]
        return _PASSWORD_CATEGORY_DESCRIPTIONS.get(category, "User has a cracked password")

    def _add_delegation_details(self, category, entity_details, risk_object):
        delegation_categories = [
            "User with Constrained Delegation",
            "Computer with Constrained Delegation",
            "User with Weak Password and Constrained Delegation"
        ]

        if category in delegation_categories:
            delegation_info = entity_details.get('constrainedDelegation')

            if delegation_info:
                risk_object["details"]["delegation_info"] = delegation_info
                return True

        return False
