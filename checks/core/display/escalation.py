from collections import defaultdict
from colorama import Style
from ..constants import DataTypes, DisplaySymbols, is_sid
from modules.node_type_cache import extract_ad_report_type_from_labels


class EscalationPathDisplayHandler:
    def __init__(self, suppress_terminal_output=False, check_instance=None, sid_mapper=None):
        self.suppress_terminal_output = suppress_terminal_output
        self.check_instance = check_instance
        self.sid_mapper = sid_mapper

    def display(self, results, category_color, category, content, count, reset_color):
        if not self.suppress_terminal_output:
            print(f"\n  {Style.BRIGHT}{category_color}{category}: {count}{reset_color}")
        content.append(f"\n  {category}: {count}")

        for entity_identifier, item_data in results.items():
            if isinstance(item_data, dict):
                description = item_data.get('description', '')
            else:
                description = item_data

            display_info = description.split(" (")[-1][:-1] if " (" in description and description.endswith(")") else description if description else ""
            display_name = self.sid_mapper.get_display_name(entity_identifier)

            if display_info:
                line = f"{DisplaySymbols.MAIN_ITEM}{display_name} ({display_info})"
            else:
                line = f"{DisplaySymbols.MAIN_ITEM}{display_name}"
            if not self.suppress_terminal_output:
                print(line)
            content.append(line)

            escalation_paths = self._get_escalation_path_details(entity_identifier)
            if escalation_paths:
                # path is [Node, Rel, Node, Rel, Node] — count relationships not elements
                steps = len(escalation_paths) // 2
                final_target = escalation_paths[-1] if escalation_paths else "Unknown"

                leads_line = f"         {DisplaySymbols.PATH_CONNECTOR} LEADS TO{DisplaySymbols.PATH_ARROW}{final_target} (via {steps} steps)"
                if not self.suppress_terminal_output:
                    print(leads_line)
                content.append(leads_line)

                path_str = DisplaySymbols.PATH_ARROW.join(escalation_paths)
                path_line = f"            {DisplaySymbols.PATH_CONNECTOR} {path_str}"
                if not self.suppress_terminal_output:
                    print(path_line)
                content.append(path_line)

        return content

    def _get_escalation_path_details(self, entity_identifier):
        if not self._can_get_escalation_paths(entity_identifier):
            return None
        path_data = self._find_escalation_path_data(entity_identifier)
        if path_data:
            return self._format_escalation_path(path_data)
        return None

    def _can_get_escalation_paths(self, entity_identifier):
        if not self.check_instance:
            return False
        if DataTypes.ESCALATION_PATHS not in getattr(self.check_instance, 'REQUIRED_DATA', []):
            return False
        if not is_sid(entity_identifier):
            return False
        return True

    def _find_escalation_path_data(self, entity_sid):
        cache_locations = [
            self.check_instance.data.get(DataTypes.FULL_ESCALATION_PATHS, {}),
            getattr(self.check_instance.neo4j_data, 'user_escalation_paths_cache', {})
        ]
        for cache_data in cache_locations:
            if entity_sid in cache_data:
                path_data = cache_data[entity_sid]
                if isinstance(path_data, list) and path_data:
                    for entry in path_data:
                        if isinstance(entry, dict) and entry.get('hasEscalationPath'):
                            full_path = entry.get('fullPath', [])
                            if full_path:
                                return full_path
        return None

    def _format_escalation_path(self, full_path):
        path_elements = []
        # fullPath is interleaved: node, rel, node, rel, ..., final_node
        for item in full_path:
            if isinstance(item, dict):
                formatted_node = self._format_path_node(item)
                if formatted_node:
                    path_elements.append(formatted_node)
            elif isinstance(item, str):
                path_elements.append(item)
        return path_elements

    def _format_path_node(self, node):
        name = node.get('name', '')
        labels = node.get('labels', [])
        objectid = node.get('objectid', '')

        if name and labels:
            node_type = extract_ad_report_type_from_labels(labels)
            return f"{name} ({node_type})"
        elif name:
            return name
        elif objectid:
            if labels:
                node_type = extract_ad_report_type_from_labels(labels)
                return f"{objectid} ({node_type})"
            else:
                return objectid
        return None


class GroupedEscalationDisplayHandler:
    def __init__(self, suppress_terminal_output=False, check_instance=None, sid_mapper=None):
        self.suppress_terminal_output = suppress_terminal_output
        self.check_instance = check_instance
        self.sid_mapper = sid_mapper

    def display(self, results, category_color, category, content, count, reset_color):
        if not results:
            return content

        if not self.suppress_terminal_output:
            print(f"\n  {Style.BRIGHT}{category_color}{category}: {count}{reset_color}")
        content.append(f"\n  {category}: {count}")

        entity_type = getattr(self.check_instance, 'ENTITY_TYPE', 'user')
        entity_label = "Computers" if entity_type == 'computer' else "Users"

        path_to_entities = defaultdict(set)

        for entity_sid, result in results.items():
            entity_name = self.sid_mapper.get_display_name(entity_sid)

            path_data = self._get_escalation_path(entity_sid)
            if not path_data:
                continue

            normalized_path = self._normalize_path(path_data)
            if normalized_path:
                path_to_entities[normalized_path].add(entity_name)

        if not path_to_entities:
            return content

        sorted_paths = sorted(
            path_to_entities.items(),
            key=lambda item: len(item[1]),
            reverse=True
        )

        for path_str, entities_set in sorted_paths:
            sorted_entities = sorted(entities_set)
            entities_str = ", ".join(sorted_entities)
            entities_count = len(entities_set)

            line1 = f"    {entity_label} with Shared Path ({entities_count}): {entities_str}"
            if not self.suppress_terminal_output:
                print(line1)
            content.append(line1)

            line2 = f"        Common Escalation Path: {path_str}\n"
            if not self.suppress_terminal_output:
                print(line2)
            content.append(line2)

        return content

    def _get_escalation_path(self, entity_sid):
        full_paths = self.check_instance.data.get(DataTypes.FULL_ESCALATION_PATHS, {})
        if entity_sid in full_paths:
            path_list = full_paths[entity_sid]
            if isinstance(path_list, list) and len(path_list) > 0:
                if isinstance(path_list[0], dict) and 'fullPath' in path_list[0]:
                    return path_list[0]['fullPath']

        cache = getattr(self.check_instance.neo4j_data, 'user_escalation_paths_cache', {})
        if entity_sid in cache:
            path_list = cache[entity_sid]
            if isinstance(path_list, list) and len(path_list) > 0:
                if isinstance(path_list[0], dict) and 'fullPath' in path_list[0]:
                    return path_list[0]['fullPath']

        return None

    def _normalize_path(self, path_array):
        if not path_array:
            return None

        path_array = [item for item in path_array if item is not None]
        if not path_array:
            return None

        clean_path_parts = []

        for i, item in enumerate(path_array):
            if i % 2 == 0:
                if isinstance(item, dict):
                    formatted = self._format_path_node(item)
                    if formatted:
                        clean_path_parts.append(formatted)
                elif isinstance(item, str):
                    clean_name = item.split('@')[0] if '@' in item else item
                    if not (' (' in item and item.endswith(')')):
                        item = f"{clean_name} (Unknown)"
                    clean_path_parts.append(item)
            else:
                clean_path_parts.append(str(item))

        if len(clean_path_parts) > 1:
            return " -> ".join(clean_path_parts[1:])
        else:
            return ""

    def _format_path_node(self, node):
        name = node.get('name', '')
        labels = node.get('labels', [])

        if not name:
            name = node.get('objectid', '')
            if not name:
                return None

        if '@' in name:
            name = name.split('@')[0]
        elif '.' in name and not name.startswith('.'):
            parts = name.split('.')
            if len(parts) > 2 and all(len(p) > 1 for p in parts[-2:]):
                name = parts[0]

        node_type = extract_ad_report_type_from_labels(labels) if labels else 'Unknown'

        return f"{name} ({node_type})"
