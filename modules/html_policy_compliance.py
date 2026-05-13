import html
from datetime import datetime


class PolicyComplianceMixin:
    def _create_metric_card(self, value, label, tooltip, clickable=False, onclick_action=None):
        card_classes = "metric-card hoverable-username"
        if clickable:
            card_classes += " clickable"

        onclick_attr = f' onclick="{onclick_action}"' if clickable and onclick_action else ''
        escaped_tooltip = self._escape_tooltip(tooltip)

        return [
            f'<div class="{card_classes}"{onclick_attr} data-tooltip="{escaped_tooltip}">',
            f'<div class="metric-value">{value}</div>',
            f'<div class="metric-label">{label}</div>',
            '</div>'
        ]

    def _create_metrics_tooltip(self, title, count, description, user_list=None, click_hint=None):
        tooltip = f"<strong>{title}:</strong> {count}<br><br>{description}"
        if user_list:
            user_items = "<br>".join([f"• {user}" for user in sorted(user_list)])
            tooltip += f"<br><br><strong>Accounts:</strong><br>{user_items}"
        if click_hint:
            tooltip += f"<br><br>{click_hint}"
        return tooltip

    def _build_policy_violations_data(self):
        violations_data = []
        sorted_usernames = sorted(
            self.account_analysis.cracked_accounts.keys(),
            key=lambda username: len(self.account_analysis.cracked_accounts.get(username, ''))
        )

        all_violation_types = set()
        has_blank_passwords = False
        has_non_blank_patterns = False
        has_lm_hash_patterns = False
        for username in self.account_analysis.cracked_accounts.keys():
            username_lower = username.lower()
            user_data = self.user_details.get(username_lower, {})
            if not user_data.get('enabled', False):
                continue

            violations = self.policy_analyzer.analyze_user_violations(username)
            violation_types = {v['type'] for v in violations}
            all_violation_types.update(violation_types)

            for violation in violations:
                if violation['type'] == 'pattern':
                    if violation.get('pattern_type', '') == 'blank_password':
                        if not has_blank_passwords:
                            has_blank_passwords = True
                    elif violation.get('pattern_type', '') == 'lm_hash_configured':
                        if not has_lm_hash_patterns:
                            has_lm_hash_patterns = True
                    else:
                        if not has_non_blank_patterns:
                            has_non_blank_patterns = True

                    if has_blank_passwords and has_non_blank_patterns and has_lm_hash_patterns:
                        break

        for username in sorted_usernames:
            violations = self.policy_analyzer.analyze_user_violations(username)

            username_lower = username.lower()
            user_data = self.user_details.get(username_lower, {})

            if not user_data.get('enabled', False):
                continue

            if self.output_format == 'safe':
                password_length = len(self.account_analysis.cracked_accounts.get(username, ''))
            else:
                password = self.account_analysis.cracked_accounts.get(username, '')
                password_length = len(password)

            if 'passwordLastChanged' in user_data and user_data['passwordLastChanged']:
                try:
                    last_set = datetime.fromtimestamp(int(user_data['passwordLastChanged'])).strftime('%Y-%m-%d %H:%M:%S')
                except (ValueError, TypeError):
                    last_set = 'Never'
            else:
                last_set = 'Never'

            violation_types = set(violation['type'] for violation in violations) if violations else set()

            # +1 baseline for every cracked password, then +1 per matched violation type
            total_violation_count = len(violations) if violations else 0
            total_violation_count += 1

            has_length_violation = 'length' in violation_types
            has_admin_violation = 'admin_account' in violation_types
            has_privileged_violation = 'privileged_account' in violation_types
            has_kerberoastable_violation = 'kerberoastable_account' in violation_types
            has_asrep_violation = 'asrep_roastable_account' in violation_types
            has_likely_username_violation = 'likely_username' in violation_types

            has_blank_password_violation = False
            has_lm_hash_violation = False
            if violations:
                for violation in violations:
                    if violation['type'] == 'pattern':
                        if violation.get('pattern_type', '') == 'blank_password':
                            has_blank_password_violation = True
                        elif violation.get('pattern_type', '') == 'lm_hash_configured':
                            has_lm_hash_violation = True

            pattern_violation_detail = 'No'
            if violations:
                for violation in violations:
                    if violation['type'] == 'pattern' and violation.get('pattern_type', '') not in ['blank_password', 'lm_hash_configured']:
                        pattern_violation_detail = violation['message']
                        break

            row_data = {
                'Username': username,
                'Password Length': password_length,
                'Last Password Change': last_set,
                'Enabled': user_data.get('enabled', 'Unknown'),
                'Violation Count': total_violation_count,
            }

            if 'length' in all_violation_types:
                row_data['Length_Violation'] = 'Yes' if has_length_violation else 'No'
            if 'admin_account' in all_violation_types:
                row_data['Admin_Account'] = 'Yes' if has_admin_violation else 'No'
            if 'privileged_account' in all_violation_types:
                row_data['Privileged_Account'] = 'Yes' if has_privileged_violation else 'No'
            if 'kerberoastable_account' in all_violation_types:
                row_data['Kerberoastable_Account'] = 'Yes' if has_kerberoastable_violation else 'No'
            if 'asrep_roastable_account' in all_violation_types:
                row_data['AS-REP_Roastable_Account'] = 'Yes' if has_asrep_violation else 'No'
            if 'likely_username' in all_violation_types:
                row_data['Likely_Username'] = 'Yes' if has_likely_username_violation else 'No'
            if has_blank_passwords:
                row_data['Blank_Password'] = 'Yes' if has_blank_password_violation else 'No'
            if has_lm_hash_patterns:
                row_data['LM_Hash_Enabled'] = 'Yes' if has_lm_hash_violation else 'No'

            if has_non_blank_patterns:
                row_data['Pattern_Violation'] = pattern_violation_detail

            row_data['Cracked_Password'] = 'Yes'

            violations_data.append(row_data)

        violations_data.sort(key=lambda x: (-x['Violation Count'], x['Username']))
        return violations_data

    def generate_policy_compliance_content(self):
        content = []

        if self.policy_analyzer.domain_properties:
            content.append('<div class="policy-summary">')
            content.append('<h3>Domain Policy Settings</h3>')
            content.append('<div class="policy-grid">')

            policy_labels = {
                'maxpwdage': 'Max Password Age',
                'minpwdage': 'Min Password Age',
                'minpwdlength': 'Min Password Length',
                'pwdhistorylength': 'Password History',
                'lockoutthreshold': 'Lockout Threshold',
                'lockoutduration': 'Lockout Duration',
                'lockoutobservationwindow': 'Lockout Window',
                'machineaccountquota': 'Machine Account Quota'
            }

            for key, value in self.policy_analyzer.domain_properties.items():
                label = policy_labels.get(key, key.title())
                content.append(f'<div class="policy-item"><strong>{label}:</strong> {value}</div>')

            content.append('</div>')
            content.append('</div>')

        stats = self.policy_analyzer.get_compliance_statistics()

        pattern_breakdown = {}
        privileged_users = set()
        admin_users = set()
        kerberoastable_users = set()
        asrep_roastable_users = set()
        likely_username_users = set()
        blank_password_users = set()
        lm_hash_users = set()

        for username in self.account_analysis.cracked_accounts:
            username_lower = username.lower()
            user_data = self.user_details.get(username_lower, {})
            if not user_data.get('enabled', False):
                continue

            violations = self.policy_analyzer.analyze_user_violations(username)
            for violation in violations:
                if violation['type'] == 'pattern':
                    pattern_category = violation.get('pattern_type', '')
                    if pattern_category != 'lm_hash_configured':
                        pattern_type = violation.get('pattern_text', 'Unknown')
                        pattern_breakdown[pattern_type] = pattern_breakdown.get(pattern_type, 0) + 1
                    if pattern_category == 'blank_password':
                        blank_password_users.add(username)
                    elif pattern_category == 'lm_hash_configured':
                        lm_hash_users.add(username)
                elif violation['type'] == 'privileged_account':
                    privileged_users.add(username)
                elif violation['type'] == 'admin_account':
                    admin_users.add(username)
                elif violation['type'] == 'kerberoastable_account':
                    kerberoastable_users.add(username)
                elif violation['type'] == 'asrep_roastable_account':
                    asrep_roastable_users.add(username)
                elif violation['type'] == 'likely_username':
                    likely_username_users.add(username)

        content.append('<div class="metrics-section">')
        content.append('<h3>Policy Compliance Metrics</h3>')
        content.append('<div class="metrics-cards">')

        tooltip_total = self._create_metrics_tooltip(
            "Total Cracked Passwords", stats['total_cracked'],
            "Total passwords that have been successfully cracked.",
            click_hint="Click to view all weak passwords in the Password Audit tab."
        )
        content.extend(self._create_metric_card(
            stats["total_cracked"],
            "Total Cracked",
            tooltip_total,
            clickable=True,
            onclick_action="navigateToSection('Password Audit', 'weak_passwords-section')"
        ))

        min_length = self.policy_analyzer.domain_properties.get('minpwdlength')
        if stats["length_violations"] > 0 and min_length is not None:
            tooltip_length = self._create_metrics_tooltip(
                "Length Violations", stats['length_violations'],
                f"Passwords shorter than the minimum required length of {min_length} characters.",
                click_hint="Click to view password length statistics."
            )
            content.extend(self._create_metric_card(
                stats["length_violations"],
                "Length Violations",
                tooltip_length,
                clickable=True,
                onclick_action="openTab(event, 'PasswordStatistics')"
            ))

        pattern_details = "<br>".join([f"{pattern}: {count}" for pattern, count in sorted(pattern_breakdown.items())])
        pattern_description = f"Breakdown by category:<br>{pattern_details}<br><br>Passwords matching common categories such as seasons, months, days, company names, usernames, and generic password patterns."
        tooltip_pattern = self._create_metrics_tooltip(
            "Predictable Patterns", stats['pattern_violations'], pattern_description
        )
        content.extend(self._create_metric_card(
            stats["pattern_violations"],
            "Predictable Patterns",
            tooltip_pattern
        ))

        if len(admin_users) > 0:
            admin_count = len(admin_users)
            tooltip_admin = self._create_metrics_tooltip(
                "Admin Account Violations", admin_count,
                "Admin accounts with weak passwords pose the highest security risk as they provide full administrative access to systems and data.",
                user_list=admin_users
            )
            content.extend(self._create_metric_card(
                admin_count,
                "Admin Accounts",
                tooltip_admin
            ))

        if len(privileged_users) > 0:
            privileged_count = len(privileged_users)
            tooltip_privileged = self._create_metrics_tooltip(
                "Privileged Account Violations", privileged_count,
                "Privileged accounts with weak passwords pose elevated security risk as they provide indirect access to sensitive systems and data.",
                user_list=privileged_users
            )
            content.extend(self._create_metric_card(
                privileged_count,
                "Privileged Accounts",
                tooltip_privileged
            ))

        content.append('</div>')
        content.append('</div>')

        content.append('<div class="violation-explanation">')
        content.append('<h4>How Violation Counts Work</h4>')
        content.append('<p>Each account with a cracked password gets a violation count:</p>')
        content.append('<ul class="violation-list">')

        violations_shown = 0

        min_pwd_length_policy = self.policy_analyzer.domain_properties.get('minpwdlength')
        if min_pwd_length_policy is not None and min_pwd_length_policy > 0 and stats.get('length_violations', 0) > 0:
            content.append(f'<li><strong>+1</strong> Password too short (below {min_pwd_length_policy} characters)</li>')
            violations_shown += 1

        if len(admin_users) > 0 or len(privileged_users) > 0:
            content.append('<li><strong>+1</strong> Admin or privileged account</li>')
            violations_shown += 1

        if len(kerberoastable_users) > 0:
            content.append('<li><strong>+1</strong> Kerberoastable account</li>')
            violations_shown += 1

        if len(asrep_roastable_users) > 0:
            content.append('<li><strong>+1</strong> AS-REP Roastable account</li>')
            violations_shown += 1

        if len(likely_username_users) > 0:
            content.append('<li><strong>+1</strong> Statistically likely username</li>')
            violations_shown += 1

        if len(blank_password_users) > 0:
            content.append('<li><strong>+1</strong> Blank/empty password</li>')
            violations_shown += 1

        if len(lm_hash_users) > 0:
            content.append('<li><strong>+1</strong> LM Hash authentication enabled</li>')
            violations_shown += 1

        if stats.get('pattern_violations', 0) > 0:
            content.append('<li><strong>+1</strong> Weak password pattern (like "password", "welcome", seasons, etc.)</li>')
            violations_shown += 1

        content.append('<li><strong>+1</strong> Password was cracked using publically available wordlists</li>')
        violations_shown += 1

        content.append('</ul>')
        content.append(f'<p class="note"><em>Maximum count: {violations_shown} violations per account. Higher numbers mean greater security risks.</em></p>')
        content.append('</div>')

        content.append('<div class="csv-download-section">')
        content.append('<button id="downloadPolicyCSV" class="csv-download-btn" onclick="downloadPolicyViolationsCSV()">')
        content.append('<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">')
        content.append('<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>')
        content.append('<polyline points="7,10 12,15 17,10"></polyline>')
        content.append('<line x1="12" y1="15" x2="12" y2="3"></line>')
        content.append('</svg>')
        content.append('Download Policy Violations CSV')
        content.append('</button>')
        content.append('</div>')

        content.append('<div class="violations-table-container">')
        content.append('<h3>Policy Violations by User</h3>')
        content.append('<table class="violations-table">')
        content.append('<thead>')
        content.append('<tr>')
        content.append('<th>Username</th>')
        if self.output_format == 'unsafe':
            content.append('<th>Password</th>')
        content.append('<th>Length</th>')
        content.append('<th>Last Set</th>')
        content.append('<th>Violations</th>')
        content.append('</tr>')
        content.append('</thead>')
        content.append('<tbody>')

        sorted_usernames = sorted(
            self.account_analysis.cracked_accounts.keys(),
            key=lambda username: len(self.account_analysis.cracked_accounts.get(username, ''))
        )

        for username in sorted_usernames:
            violations = self.policy_analyzer.analyze_user_violations(username)

            username_lower = username.lower()
            user_data = self.user_details.get(username_lower, {})
            if not user_data.get('enabled', False):
                continue

            content.append('<tr>')

            hoverable_username = self.make_username_hoverable(username)
            content.append(f'<td>{hoverable_username}</td>')

            if self.output_format == 'unsafe':
                password = self.account_analysis.cracked_accounts.get(username, '')
                content.append(f'<td>{html.escape(password)}</td>')

            if self.output_format == 'safe':
                password_length = len(self.account_analysis.cracked_accounts.get(username, ''))
            else:
                password = self.account_analysis.cracked_accounts.get(username, '')
                password_length = len(password)
            content.append(f'<td>{password_length}</td>')

            user_data = self.user_details.get(username.lower(), {})
            if 'passwordLastChanged' in user_data and user_data['passwordLastChanged']:
                try:
                    last_set = datetime.fromtimestamp(int(user_data['passwordLastChanged'])).strftime('%Y-%m-%d')
                except (ValueError, TypeError):
                    last_set = 'Never'
            else:
                last_set = 'Never'
            content.append(f'<td>{last_set}</td>')

            violations_html = []

            if not violations:
                violations_html.append(f'<span class="violation-badge clickable-violation" onclick="navigateToSection(\'User Account Analysis\', \'likely_usernames-section\', \'Statistically Likely Usernames\')" title="Click to see all statistically likely usernames">Password Cracked using Public Wordlist</span>')
            else:
                for violation in violations:
                    if violation['type'] == 'pattern' and 'pattern_type' in violation:
                        pattern_type = violation.get('pattern_type', '')
                        pattern_text = violation['pattern_text']

                        if pattern_type == 'lm_hash_configured':
                            violations_html.append(f'<span class="violation-badge clickable-violation" onclick="navigateToSection(\'Password Audit\', \'lm_hash-section\', \'LM Hash Authentication Enabled\')" title="Click to see all users with LM Hash authentication enabled">{violation["message"]}</span>')
                        else:
                            section_id = 'category_accounts-section'
                            violations_html.append(f'<span class="violation-badge clickable-violation" onclick="navigateToSection(\'Password Audit\', \'{section_id}\', \'{pattern_text}\')" title="Click to see all users with {pattern_text}-containing passwords">{violation["message"]}</span>')
                    elif violation['type'] == 'blank':
                        violations_html.append(f'<span class="violation-badge clickable-violation" onclick="navigateToSection(\'Password Audit\', \'category_accounts-section\', \'blank password\')" title="Click to see all users with blank passwords">{violation["message"]}</span>')
                    elif violation['type'] == 'admin_account':
                        violations_html.append(f'<span class="violation-badge clickable-violation" onclick="navigateToSection(\'Password Audit\', \'cracked_admins-section\', \'Cracked Admin Accounts (Group Membership):\')" title="Click to see all admin accounts with weak passwords">{violation["message"]}</span>')
                    elif violation['type'] == 'privileged_account':
                        violations_html.append(f'<span class="violation-badge clickable-violation" onclick="navigateToSection(\'Password Audit\', \'cracked_privileged-section\', \'Cracked Privileged Accounts (Indirect Access):\')" title="Click to see all privileged accounts with weak passwords">{violation["message"]}</span>')
                    elif violation['type'] == 'likely_username':
                        violations_html.append(f'<span class="violation-badge clickable-violation" onclick="navigateToSection(\'User Account Analysis\', \'likely_usernames-section\', \'Statistically Likely Usernames\')" title="Click to see all statistically likely usernames">{violation["message"]}</span>')
                    elif violation['type'] == 'kerberoastable_account':
                        violations_html.append(f'<span class="violation-badge clickable-violation" onclick="navigateToSection(\'User Account Analysis\', \'kerberoastable_accounts-section\', \'Kerberoastable Accounts\')" title="Click to see all kerberoastable accounts">{violation["message"]}</span>')
                    elif violation['type'] == 'asrep_roastable_account':
                        violations_html.append(f'<span class="violation-badge clickable-violation" onclick="navigateToSection(\'User Account Analysis\', \'asrep_roastable_accounts-section\', \'AS-REP Roastable Accounts\')" title="Click to see all AS-REP roastable accounts">{violation["message"]}</span>')
                    elif violation['type'] == 'length':
                        violations_html.append(f'<span class="violation-badge clickable-violation" onclick="navigateToSection(\'Password Statistics\', \'PasswordStatistics\', \'Password Length Analysis\')" title="Click to see password length statistics">{violation["message"]}</span>')
                    else:
                        violations_html.append(f'<span class="violation-badge">{violation["message"]}</span>')

            content.append(f'<td>{"".join(violations_html)}</td>')

            content.append('</tr>')

        content.append('</tbody>')
        content.append('</table>')
        content.append('</div>')

        return content
