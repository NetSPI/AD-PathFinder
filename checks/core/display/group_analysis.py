from colorama import Style


class GroupAnalysisDisplayHandler:
    def __init__(self, suppress_terminal_output=False, check_instance=None, sid_mapper=None):
        self.suppress_terminal_output = suppress_terminal_output
        self.check_instance = check_instance
        self.sid_mapper = sid_mapper
        self.reset_color = ""
        self._account_analysis = getattr(check_instance, 'account_analysis', None)

    def display(self, results, category_color, category, content, count, reset_color):
        self.reset_color = reset_color
        enhanced_data = results.get("___enhanced_data___", {})
        display_groups = {k: v for k, v in results.items() if not k.startswith("___")}
        group_count = len(display_groups)

        if not self.suppress_terminal_output:
            print(f"\n  {Style.BRIGHT}{category_color}{category}: {group_count}{reset_color}")
        content.append(f"\n  {category}: {group_count}")

        enhanced_data_ci = {k.upper(): k for k in enhanced_data.keys()}

        for group_type, paths in display_groups.items():
            if not paths:
                continue

            self._output_line(f"\n    ▶ {group_type}", content)

            enhanced_paths = enhanced_data.get(group_type, [])
            if not enhanced_paths and group_type.upper() in enhanced_data_ci:
                enhanced_paths = enhanced_data.get(enhanced_data_ci[group_type.upper()], [])

            enhanced_sid_lookup = {}
            for ep in enhanced_paths:
                target_sid = ep.get('targetSID')
                if target_sid:
                    enhanced_sid_lookup[target_sid] = ep

            path_count = len(paths)
            for idx, path_obj in enumerate(paths):
                if not isinstance(path_obj, dict):
                    continue

                is_last = idx == path_count - 1
                path_prefix = "      └─" if is_last else "      ├─"
                cont_prefix = "         " if is_last else "      │  "

                rel_type = path_obj.get('rel_type', 'Unknown')
                target = path_obj.get('target', 'Unknown')
                target_sid = path_obj.get('targetSID', '')
                has_esc = path_obj.get('targetHasEscalationPath', False)
                esc_path = path_obj.get('targetEscalationPath', [])

                target_type = self._account_analysis._resolve_target_type(
                    target, target_sid, enhanced_sid_lookup, enhanced_paths
                )
                if target_type and not (target.endswith(')') and f'({target_type})' in target):
                    self._output_line(f"{path_prefix} {rel_type} on {target} ({target_type})", content)
                else:
                    self._output_line(f"{path_prefix} {rel_type} on {target}", content)

                self._render_db_details(path_obj, cont_prefix, has_esc, esc_path, content)
                self._render_escalation(esc_path, has_esc, cont_prefix, content)

        return content

    def _render_db_details(self, path_obj, cont_prefix, has_esc, esc_path, content):
        db_name = path_obj.get('databaseName')
        if not db_name:
            return

        db_roles = path_obj.get('databaseRoles', [])
        db_trustworthy = path_obj.get('databaseIsTrustworthy', False)
        db_perms = path_obj.get('databaseUserPermissions', [])

        roles_str = ', '.join(db_roles) if db_roles else 'public'
        trustworthy_marker = ' [TRUSTWORTHY]' if db_trustworthy else ''
        db_connector = "├─" if (has_esc and esc_path) else "└─"
        self._output_line(
            f"{cont_prefix} {db_connector} Database Access: {db_name} (Roles: {roles_str}){trustworthy_marker}",
            content
        )

        if db_perms:
            perms_str = ', '.join(db_perms)
            perm_cont = f"{cont_prefix} │  " if (has_esc and esc_path) else f"{cont_prefix}    "
            self._output_line(f"{perm_cont}└─ Permissions: {perms_str}", content)

    def _render_escalation(self, esc_path, has_esc, cont_prefix, content):
        if not (has_esc and esc_path):
            return

        steps = len(esc_path) // 2
        if steps == 0 and len(esc_path) >= 2:
            steps = 1

        final = self._account_analysis._get_final_target_info(esc_path)
        esc_str = self._account_analysis._format_escalation_path(esc_path)

        if final['type']:
            self._output_line(
                f"{cont_prefix} └─ LEADS TO -> {final['name']} ({final['type']}) (via {steps} steps)",
                content
            )
        else:
            self._output_line(
                f"{cont_prefix} └─ LEADS TO -> {final['name']} (via {steps} steps)",
                content
            )
        self._output_line(f"{cont_prefix}    └─ {esc_str}", content)

    def _output_line(self, line, content):
        if not self.suppress_terminal_output:
            print(f"{self.reset_color}{line}")
        content.append(line)
