class AdminPathProcessor:

    @staticmethod
    def group_admin_paths_from_records(admin_records):
        grouped_paths = {}
        for record in admin_records:
            source_name = record.get('SourceFQDN') or record.get('SourceComputer') or 'Unknown'
            target_name = record.get('TargetFQDN') or record.get('TargetComputer') or 'Unknown'
            relationship = record.get('RelationshipType') or 'Unknown'

            path = f"{source_name} -> {relationship} -> {target_name}"
            key = f"{source_name}->{target_name}"

            if key not in grouped_paths:
                grouped_paths[key] = []
            grouped_paths[key].append(path)
        return grouped_paths

    @staticmethod
    def format_grouped_paths_hierarchical(grouped_paths):
        formatted_lines = []

        for key, paths_group in grouped_paths.items():
            # DirectAdminTo first so the primary relationship is always the header line
            paths_sorted = sorted(paths_group, key=lambda x: 0 if 'DirectAdminTo' in x else 1)

            for i, path in enumerate(paths_sorted):
                if i == 0:
                    formatted_lines.append(path)
                else:
                    formatted_lines.append(f"            └─ {path}")

        return "\n".join(formatted_lines)

    @staticmethod
    def format_inline_admin_description(admin_records):
        if not admin_records:
            return None

        if len(admin_records) == 1:
            target_computer = admin_records[0].get('TargetFQDN') or admin_records[0].get('TargetComputer') or 'Unknown'
            relationship_type = admin_records[0].get('RelationshipType') or 'AdminTo'
            return f"-> {relationship_type} -> {target_computer}"
        else:
            targets = [record.get('TargetFQDN') or record.get('TargetComputer') or 'Unknown' for record in admin_records]
            targets_str = ', '.join(targets)
            return f"-> AdminTo -> {targets_str}"


class AdminDisplayStrategy:

    @staticmethod
    def should_use_hierarchical_display(admin_records, entity_type='computer'):
        if not admin_records:
            return False

        relationship_types = {record.get('RelationshipType') or '' for record in admin_records}
        has_multiple_types = len(relationship_types) > 1
        has_group_relationships = any(' > ' in rt for rt in relationship_types)
        has_ntlm_relay = any('NTLMRelay' in rt for rt in relationship_types)

        if entity_type == 'computer':
            return has_multiple_types or has_group_relationships or has_ntlm_relay
        if entity_type == 'user':
            return (len(admin_records) > 3) or has_group_relationships
        return False

    @staticmethod
    def format_admin_display(admin_records, entity_type='computer'):
        if not admin_records:
            return None
        use_hierarchical = AdminDisplayStrategy.should_use_hierarchical_display(
            admin_records, entity_type
        )
        if use_hierarchical:
            grouped_paths = AdminPathProcessor.group_admin_paths_from_records(admin_records)
            description = AdminPathProcessor.format_grouped_paths_hierarchical(grouped_paths)
            return {'format_type': 'hierarchical', 'description': description}
        else:
            description = AdminPathProcessor.format_inline_admin_description(admin_records)
            return {'format_type': 'inline', 'description': description}
