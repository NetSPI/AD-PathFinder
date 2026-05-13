from colorama import Fore, Style


class AccountDisplayMixin:

    def create_risk_profiles(self, shared_accounts_summary):
        report_lines = []
        all_user_data = self.get_all_user_data()
        self.ensure_user_details_populated()

        users_in_shared_accounts = set()
        if shared_accounts_summary:
            for user_list in shared_accounts_summary.values():
                users_in_shared_accounts.update(user.lower() for user in user_list)

        self.users_in_shared_accounts = users_in_shared_accounts

        has_escalation_path_results = self.check_escalation_path(
            all_user_data=all_user_data,
            user_escalation_paths=self._escalation_paths_cache,
            return_all_paths=False,
            quiet=False,
            force_refresh=False
        )
        self._escalation_results_cache = has_escalation_path_results

        self._run_framework_checks()

        organised_risk_profiles = self._organise_risk_profiles()
        self._cached_organised_risk_profiles = organised_risk_profiles

        stats = self._calculate_stats(organised_risk_profiles)
        stats_report = self._display_stats(stats)
        report_lines.append(stats_report)

        risk_profiles_report = self._display_organised_risk_profiles(organised_risk_profiles)
        report_lines.append(risk_profiles_report)

        return "\n".join(report_lines).strip(), organised_risk_profiles

    def create_password_risk_profiles(self, shared_accounts_summary):
        report_lines = []
        self.ensure_user_details_populated()

        users_in_shared_accounts = set()
        if shared_accounts_summary:
            for user_list in shared_accounts_summary.values():
                users_in_shared_accounts.update(user.lower() for user in user_list)

        self.users_in_shared_accounts = users_in_shared_accounts

        organised_risk_profiles = self._organise_risk_profiles()

        stats = self._calculate_stats(organised_risk_profiles)
        stats_report = self._display_stats(stats)
        report_lines.append(stats_report)

        risk_profiles_report = self._display_organised_risk_profiles(organised_risk_profiles)
        report_lines.append(risk_profiles_report)

        return "\n".join(report_lines).strip(), organised_risk_profiles

    def _calculate_stats(self, organised_risk_profiles):

        stats = {level: {
            'total_users': 0,
            'total_computers': 0,
            'total': 0,
            'reasons': {},
            'builtin_groups': 0
        } for level in organised_risk_profiles}

        if hasattr(self, '_framework_categories_for_stats'):
            for level, framework_categories in self._framework_categories_for_stats.items():
                if level in stats:
                    for category_name, category_data in framework_categories.items():
                        count = category_data['count']
                        entity_type = category_data.get('entity_type', 'computer')

                        stats[level]['reasons'][category_name] = count

                        if entity_type == 'computer':
                            stats[level]['total_computers'] += count
                        elif entity_type == 'user':
                            stats[level]['total_users'] += count
                        elif entity_type == 'group':
                            stats[level]['builtin_groups'] += count
                        else:
                            stats[level]['total_computers'] += count

                        stats[level]['total'] += count

        return stats

    def _display_stats(self, stats):
        report_lines = [f"{Style.BRIGHT}Risk Profile Statistics:{self.reset_color}"]

        if not getattr(self, 'suppress_terminal_output', False):
            print(f"\n{Style.BRIGHT}Risk Profile Statistics:{self.reset_color}")

        for level, data in stats.items():
            total = data['total_users'] + data['total_computers'] + data['builtin_groups']
            color = self.risk_colors.get(level, Fore.WHITE)

            if not getattr(self, 'suppress_terminal_output', False):
                print(f"\n{Style.BRIGHT}{color}{level}:{self.reset_color} Total Users - {data['total_users']}, Total Computers - {data['total_computers']}, Default Groups - {data['builtin_groups']}, Total - {total}")

            report_lines.append(f"\n{level}: Total Users - {data['total_users']}, Total Computers - {data['total_computers']}, Default Groups - {data['builtin_groups']}, Total - {total}")

            sorted_reasons = sorted(data['reasons'].items(), key=lambda item: (-item[1], item[0]))

            for reason, count in sorted_reasons:
                if count > 0:
                    if not getattr(self, 'suppress_terminal_output', False):
                        print(f"  {color}{reason}: {count}{self.reset_color}")
                    report_lines.append(f"  {reason}: {count}")

        return "\n".join(report_lines)

    def _organise_risk_profiles(self):
        return {'Critical': {}, 'High': {}, 'Medium': {}, 'Low': {}, 'Info': {}}

    def _display_organised_risk_profiles(self, organised_risk_profiles):

        content = []

        for level, categories in organised_risk_profiles.items():
            category_color = self.risk_colors.get(level, Fore.WHITE)
            title_line = f"\n{Style.BRIGHT}{category_color}{level} Risk Profiles:{self.reset_color}"

            if not getattr(self, 'suppress_terminal_output', False):
                print(title_line)

            content.append(title_line)

            content = self._display_framework_content(level, content)

        return "\n".join(content)

    def _run_framework_checks(self):
        try:
            from checks.core.manager import VulnerabilityFrameworkManager

            escalation_path_data = self._escalation_results_cache

            if not escalation_path_data:
                escalation_path_data = {
                    sid: bool(paths and any(p.get('hasEscalationPath', False) for p in paths if isinstance(p, dict)))
                    for sid, paths in self._escalation_paths_cache.items()
                }

            full_escalation_cache = self._escalation_paths_cache
            manager = VulnerabilityFrameworkManager(self.neo4j_data, escalation_path_data, full_escalation_cache, self, diagnostics=self._diagnostics)
            fw_display, fw_stats = manager.run_all_checks()

            existing_display = getattr(self, '_framework_display_content', {})
            existing_stats = getattr(self, '_framework_categories_for_stats', {})

            for level, entries in fw_display.items():
                existing_display.setdefault(level, []).extend(entries)
            for level, cats in fw_stats.items():
                existing_stats.setdefault(level, {}).update(cats)

            self._framework_display_content = existing_display
            self._framework_categories_for_stats = existing_stats

        except Exception as e:
            print(f"Warning: Framework checks failed: {e}")
            if hasattr(self, '_diagnostics') and self._diagnostics:
                self._diagnostics.record_error("framework_checks", e)

    def _display_framework_content(self, risk_level, content):
        if not hasattr(self, '_framework_display_content') or risk_level not in self._framework_display_content:
            return content

        for display_block in self._framework_display_content[risk_level]:
            category = display_block['category']
            count = display_block['count']
            results = display_block['results']
            check_instance = display_block['check_instance']

            category_color = self.risk_colors.get(risk_level, Fore.WHITE)
            display_method = check_instance.get_display_method()
            content = display_method(results, category_color, category, content, count, self.reset_color)

        return content


    def _get_object_type_from_labels(self, labels):
        return self.type_cache._extract_type_from_labels(labels) if labels else "Unknown"

