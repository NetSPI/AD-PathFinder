from collections import defaultdict
from checks.core import Check, DisplayTypes


class GroupAnalysisCheck(Check):
    DISPLAY_TYPE = DisplayTypes.GROUP_ANALYSIS
    REQUIRED_DATA = []
    ENTITY_TYPE = 'group'

    def _process_record(self, record):
        source_group = record.get('Source Group')
        group_type = record.get('Group Type')
        target_object = record.get('Target Object')
        full_path = record.get('Full Path') or []
        target_sid = record.get('Target Object SID')
        target_dn = record.get('Target Object DN')
        target_type = record.get('Target Object Type')
        target_has_esc = record.get('Target Has Escalation Path', False)
        target_esc_path = record.get('Target Escalation Path') or []
        target_sql_server = record.get('Target SQL Server')

        if not source_group or not group_type or not target_object:
            return None
        if len(full_path) == 0 and group_type == target_object:
            return None

        display_target = target_sql_server if target_sql_server else target_object

        if full_path:
            modified = full_path.copy()
            if len(modified) >= 3 and target_sql_server:
                modified[-1] = target_sql_server
            formatted_path = self.account_analysis.normalise_path(modified)
        else:
            formatted_path = f"{str(source_group).split('@')[0]} -> {str(display_target).split('@')[0]}"

        return {
            'groupType': group_type,
            'targetName': display_target,
            'fullPath': formatted_path,
            'targetSID': target_sid,
            'targetType': target_type,
            'targetDN': target_dn,
            'targetHasEscalationPath': target_has_esc,
            'targetEscalationPath': target_esc_path,
            'databaseUserName': record.get('Database User Name'),
            'databaseName': record.get('Database Name'),
            'databaseRoles': record.get('Database Roles') or [],
            'databaseIsTrustworthy': record.get('Database Is Trustworthy', False),
            'databaseUserPermissions': record.get('Database User Permissions') or [],
        }

    def _build_results(self, processed):
        if not processed:
            return {}
        grouped_paths = defaultdict(list)
        for entry in processed:
            group_key = entry['groupType']
            parts = entry['fullPath'].split(" -> ")
            if len(parts) >= 2:
                rel_type = parts[0]
                target = parts[1]
            else:
                rel_type = ''
                target = entry['targetName']

            grouped_paths[group_key].append({
                'display': entry['fullPath'],
                'rel_type': rel_type,
                'target': target,
                'targetSID': entry['targetSID'],
                'targetHasEscalationPath': entry['targetHasEscalationPath'],
                'targetEscalationPath': entry['targetEscalationPath'],
                'databaseUserName': entry.get('databaseUserName'),
                'databaseName': entry.get('databaseName'),
                'databaseRoles': entry.get('databaseRoles') or [],
                'databaseIsTrustworthy': entry.get('databaseIsTrustworthy', False),
                'databaseUserPermissions': entry.get('databaseUserPermissions') or [],
            })

        for group_key in grouped_paths:
            seen = set()
            deduped = []
            for path in grouped_paths[group_key]:
                display = path.get('display', '')
                if display not in seen:
                    seen.add(display)
                    deduped.append(path)
            grouped_paths[group_key] = deduped

        enhanced_data = defaultdict(list)
        for entry in processed:
            enhanced_data[entry['groupType']].append(entry)

        result = dict(grouped_paths)
        result["___enhanced_data___"] = dict(enhanced_data)
        return result

    def get_count(self, results):
        if not isinstance(results, dict):
            return 0
        return sum(1 for k in results if not k.startswith("___"))
