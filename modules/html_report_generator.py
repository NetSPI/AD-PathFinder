import os
import re
import html
from .policy_compliance import PolicyComplianceAnalyzer
from .utils import get_likely_usernames
from .hv_groups import HIGH_VALUE_GROUPS_UPPER
from .sanitizer import sanitize_data_for_safe_mode
from .html_json import json_for_script as _json_for_script
from .html_password_audit import PasswordAuditMixin
from .html_policy_compliance import PolicyComplianceMixin
from .html_cross_domain import CrossDomainMixin
from .html_user_account import UserAccountAnalysisMixin


class HTMLReportGenerator(PasswordAuditMixin, PolicyComplianceMixin, CrossDomainMixin, UserAccountAnalysisMixin):
    def __init__(self, neo4j_data, account_analysis, analysis, domain_name, output_format, report_dir,
                 user_details, stats=None, ntlmv2_hashes=None, likely_usernames=None, cross_domain_data=None):
        self.neo4j_data = neo4j_data
        self.account_analysis = account_analysis
        self.user_details = user_details or {}
        self.domain_name = domain_name
        self.analysis = analysis
        self.output_format = output_format
        self.report_dir = report_dir
        self.stats = stats or {}
        self.ntlmv2_hashes = ntlmv2_hashes or {}
        self.likely_usernames = likely_usernames or []
        self.cross_domain_data = cross_domain_data or {}
        
        self.cracked_hashes = getattr(analysis, 'cracked_hashes', {})
        self.ntds_hashes = getattr(analysis, 'ntds_hashes', {})
        
        self._has_weak_password = account_analysis._has_weak_password
        self._username_regex = None
        self._username_pattern = None
    
    def create_html_data(self, organised_risk_profiles, shared_accounts_summary, user_details):
        displayed_users = set()

        for level, categories in organised_risk_profiles.items():
            for category, users in categories.items():
                if isinstance(users, dict):
                    for user_id in users.keys():
                        if user_id not in ['___enhanced_data___']:
                            displayed_users.add(user_id.lower())
        
        if shared_accounts_summary:
            for users in shared_accounts_summary.values():
                displayed_users.update(user.lower() for user in users)

        displayed_users.update(username.lower() for username in self.account_analysis.cracked_accounts.keys())

        # KRBTGT needed for password age analysis even if not cracked
        displayed_users.add('krbtgt')

        shared_with_map = {}
        if shared_accounts_summary:
            for members in shared_accounts_summary.values():
                lowered = [m.lower() for m in members]
                for user_lower in lowered:
                    others = sorted(m for m in lowered if m != user_lower)
                    if others:
                        shared_with_map[user_lower] = others

        neo4j_user_lookup = None

        tooltip_data = {}
        for user_id in displayed_users:
            if user_id in user_details:
                user_data = user_details[user_id]
                username_with_domain = user_data.get('username_with_domain') or ''
                domain = user_data.get('domain')
                if not domain:
                    domain = username_with_domain.split('@')[-1] if '@' in username_with_domain else 'UNKNOWN'
                tooltip_data[user_id] = {
                    'username': user_data.get('username', user_id),
                    'domain': domain,
                    'description': user_data.get('description', 'No description available'),
                    'enabled': user_data.get('enabled', False),
                    'isAdmin': user_data.get('isAdmin', False),
                    'groups': user_data.get('groups', []),
                    'lastLogon': user_data.get('lastLogon', 'Never'),
                    'passwordLastChanged': user_data.get('passwordLastChanged', 'Unknown'),
                    'kerberoastable': user_data.get('kerberoastable', False),
                    'asrepRoastable': user_data.get('asrepRoastable', False),
                    'adminAccessReason': user_data.get('adminAccessReason', 'N/A'),
                    'password': self.account_analysis.cracked_accounts.get(user_id, user_data.get('password')),
                    'sharedWith': shared_with_map.get(user_id, [])
                }
            else:
                if neo4j_user_lookup is None:
                    neo4j_user_lookup = {}
                    if hasattr(self.neo4j_data, 'all_users_data_cache') and self.neo4j_data.all_users_data_cache:
                        for user in self.neo4j_data.all_users_data_cache:
                            if user and user.get('username'):
                                neo4j_user_lookup[user['username'].lower()] = user

                if user_id in neo4j_user_lookup:
                    user_data = neo4j_user_lookup[user_id]
                    username_with_domain = user_data.get('username_with_domain') or ''
                    domain = username_with_domain.split('@')[-1] if '@' in username_with_domain else 'UNKNOWN'
                    tooltip_data[user_id] = {
                        'username': user_data.get('username', user_id),
                        'domain': domain,
                        'description': user_data.get('description', 'No description available'),
                        'enabled': user_data.get('enabled', False),
                        'isAdmin': user_data.get('isAdmin', False),
                        'groups': user_data.get('groups', []),
                        'lastLogon': user_data.get('lastLogon', 'Never'),
                        'passwordLastChanged': user_data.get('passwordLastChanged', 'Unknown'),
                        'kerberoastable': user_data.get('kerberoastable', False),
                        'asrepRoastable': user_data.get('asrepRoastable', False),
                        'adminAccessReason': 'N/A',
                        'password': self.account_analysis.cracked_accounts.get(user_id),
                        'sharedWith': shared_with_map.get(user_id, [])
                    }

        return tooltip_data
    
    def _escape_tooltip(self, tooltip):
        return html.escape(tooltip).replace('"', '&quot;')
    
    def _create_hoverable_tooltip_span(self, text, tooltip, additional_classes="", style=""):
        class_attr = f'class="hoverable-username{" " + additional_classes if additional_classes else ""}"'
        style_attr = f' style="{style}"' if style else ''
        escaped_tooltip = self._escape_tooltip(tooltip)
        
        return f'<span {class_attr}{style_attr} data-tooltip="{escaped_tooltip}">{html.escape(text)}</span>'
    
    def generate_html_report_with_tabs(self, report_data, password_length_data, filename, stats, shared_accounts_summary=None):
        self.stats = stats

        optimized_tooltip_data = self.create_html_data(
            organised_risk_profiles=getattr(self.account_analysis, '_cached_organised_risk_profiles', {}),
            shared_accounts_summary=shared_accounts_summary or {},
            user_details=self.user_details
        )
        
        self.user_details = optimized_tooltip_data
        self.ensure_likely_usernames()
        
        self._username_regex = None
        self._username_pattern = None
        
        self.policy_analyzer = PolicyComplianceAnalyzer(
            self.neo4j_data,
            self.account_analysis.cracked_accounts,
            self.user_details,
            self.domain_name,
            self.analysis.category_details,
            self.likely_usernames
        )
        
        current_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(current_dir)
        assets_dir = os.path.join(parent_dir, 'assets')

        css_path = os.path.join(assets_dir, 'report_styles.css')
        js_path = os.path.join(assets_dir, 'report.js')

        css_content = self.read_file_content(css_path)
        js_content = self.read_file_content(js_path)
        
        html_content = self.generate_html_content_with_tabs(report_data, password_length_data, filename, css_content, js_content)
        
        self._save_html_report('password_audit', html_content, 'html', self.output_format)
    
    def generate_html_content_with_tabs(self, report_data, password_length_data, filename, css_content, js_content):
        html_lines = []
        html_lines.append('<!DOCTYPE html>')
        html_lines.append('<html lang="en">')
        html_lines.append('<head>')
        html_lines.append('    <meta charset="UTF-8">')
        html_lines.append('    <meta http-equiv="X-UA-Compatible" content="IE=edge">')
        html_lines.append('    <meta name="viewport" content="width=device-width, initial-scale=1.0">')
        escaped_domain_name = html.escape(self.domain_name)
        html_lines.append(f'    <title>Password Analysis Report for {escaped_domain_name}</title>')
        chart_js_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'assets', 'chart.min.js')
        chart_js_content = self.read_file_content(chart_js_path)
        html_lines.append('    <script>')
        html_lines.append(chart_js_content)
        html_lines.append('    </script>')
        html_lines.append('    <style>')
        html_lines.append(css_content)
        html_lines.append('    </style>')
        html_lines.append('</head>')
        html_lines.append('<body>')
        html_lines.append('    <div id="logo-container">')
        html_lines.append('        <img src="data:image/png;base64,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" alt="Logo">')
        html_lines.append('    </div>')
        html_lines.append(f'    <h1>Password Analysis Report for {escaped_domain_name}</h1>')

        html_lines.append('    <div class="tab">')
        html_lines.append('        <button class="tablinks" onclick="openTab(event, \'PasswordAudit\')" id="defaultOpen">Password Audit</button>')
        html_lines.append('        <button class="tablinks" onclick="openTab(event, \'PolicyCompliance\')">Policy Compliance</button>')
        html_lines.append('        <button class="tablinks" onclick="openTab(event, \'PasswordStatistics\')">Password Statistics</button>')
        html_lines.append('        <button class="tablinks" onclick="openTab(event, \'UserAccountAnalysis\')">User Account Analysis</button>')
        if self.cross_domain_data:
            html_lines.append('        <button class="tablinks" onclick="openTab(event, \'CrossDomainAnalysis\')">Cross-Domain Analysis</button>')
        html_lines.append('    </div>')

        html_lines.append('    <div id="PasswordAudit" class="tabcontent">')
        html_lines.extend(self.generate_password_audit_content(report_data))
        html_lines.append('    </div>')

        html_lines.append('    <div id="PolicyCompliance" class="tabcontent">')
        html_lines.extend(self.generate_policy_compliance_content())
        html_lines.append('    </div>')

        html_lines.append('    <div id="PasswordStatistics" class="tabcontent">')
        html_lines.extend(self.generate_password_statistics_content(password_length_data))
        html_lines.append('    </div>')

        html_lines.append('    <div id="UserAccountAnalysis" class="tabcontent">')
        html_lines.extend(self.generate_user_account_analysis_content())
        html_lines.append('    </div>')

        if self.cross_domain_data:
            html_lines.append('    <div id="CrossDomainAnalysis" class="tabcontent">')
            html_lines.extend(self._generate_cross_domain_tab_content())
            html_lines.append('    </div>')

        prepared_password_length_data = {}
        for length, users in password_length_data.items():
            prepared_password_length_data[length] = []
            for user in users:
                clean_username = user.split(':')[0] if ':' in user else user
                if self.output_format == 'safe':
                    prepared_password_length_data[length].append(clean_username)
                else:
                    prepared_password_length_data[length].append(user)

        cracked_user_details = {}
        for username, details in self.user_details.items():
            username_lower = username.lower()
            if not details.get('enabled', False) and username_lower != 'krbtgt':
                continue
            user_details_copy = details.copy()
            if self.output_format == 'safe':
                if 'password' in user_details_copy:
                    user_details_copy['password'] = None
                if 'sharedWith' in user_details_copy:
                    user_details_copy['sharedWith'] = []
            cracked_user_details[username_lower] = user_details_copy

        sanitized_stats = sanitize_data_for_safe_mode(self.stats, self.output_format)
        sanitized_password_length_data = sanitize_data_for_safe_mode(prepared_password_length_data, self.output_format)
        sanitized_user_details = sanitize_data_for_safe_mode(cracked_user_details, self.output_format)
        sanitized_domain_policy = sanitize_data_for_safe_mode(self.policy_analyzer.domain_properties, self.output_format)
        sanitized_compliance_stats = sanitize_data_for_safe_mode(self.policy_analyzer.get_compliance_statistics(), self.output_format)
        sanitized_violation_distribution = sanitize_data_for_safe_mode(self.policy_analyzer.get_violation_distribution(), self.output_format)
        
        html_lines.append(f'    <script>var outputFormat = {_json_for_script(self.output_format)};</script>')
        html_lines.append(f'    <script>var stats = {_json_for_script(sanitized_stats)};</script>')
        html_lines.append(f'    <script>var passwordLengthData = {_json_for_script(sanitized_password_length_data)};</script>')
        html_lines.append(f'    <script>var userDetails = {_json_for_script(sanitized_user_details)};</script>')
        html_lines.append(f'    <script>var highValueGroupsList = {_json_for_script(sorted(HIGH_VALUE_GROUPS_UPPER))};</script>')
        html_lines.append(f'    <script>var domainName = {_json_for_script(self.domain_name)};</script>')
        html_lines.append(f'    <script>var domainPolicy = {_json_for_script(sanitized_domain_policy)};</script>')
        html_lines.append(f'    <script>var complianceStats = {_json_for_script(sanitized_compliance_stats)};</script>')
        html_lines.append(f'    <script>var violationDistribution = {_json_for_script(sanitized_violation_distribution)};</script>')
        
        sanitized_violations_data = sanitize_data_for_safe_mode(self._build_policy_violations_data(), self.output_format)
        html_lines.append(f'    <script>var policyViolationsData = {_json_for_script(sanitized_violations_data)};</script>')
        html_lines.append('    <script>')
        html_lines.append(js_content)
        html_lines.append('    </script>')
        
        html_lines.append('    <!-- Floating Back Button -->')
        html_lines.append('    <button id="backButton" class="back-button" onclick="goBack()" title="Go back to previous tab">Back</button>')
        
        html_lines.append('    <!-- Confidential Footer -->')
        html_lines.append('    <div class="confidential-footer">')
        html_lines.append('        <span>CONFIDENTIAL - This report contains sensitive security information</span>')
        html_lines.append('    </div>')
        
        html_lines.append('</body>')
        html_lines.append('</html>')

        return '\n'.join(html_lines)
    
    def _format_hash_line(self, match):
        hash_value, occurrences, password = match.groups()
        if self.output_format == 'unsafe':
            password_display = '(blank)' if password == '' else html.escape(password)
            return f"{html.escape(hash_value)} (Occurrences: <span class='occurrence'>{html.escape(occurrences)}</span>) - Password: <span class='password'>{password_display}</span>"
        else:
            return f"Group size: <span class='occurrence'>{html.escape(occurrences)}</span>"
        
    def format_line_for_html(self, line):
        hash_pattern = r'^([a-f0-9]+) \(Occurrences: (\d+)\) - Password: (.*)$'
        hash_match = re.match(hash_pattern, line)
        if hash_match:
            return self._format_hash_line(hash_match)

        user_login_pattern = r'^(.+?) - Last login: (.+)$'
        user_login_match = re.match(user_login_pattern, line)
        if user_login_match:
            return self._format_user_login_line(user_login_match)

        user_password_pattern = r'^(.+?)\s*:\s*(.*)$'
        user_password_match = re.match(user_password_pattern, line)
        if user_password_match:
            return self._format_user_password_line(user_password_match)

        escaped_line = html.escape(line)
        
        username_regex = self._get_username_regex()
        formatted_line = username_regex.sub(
            lambda match: self.make_username_hoverable(match.group(1)), 
            escaped_line
        )
        
        return formatted_line
    
    def _save_html_report(self, report_type, content, file_type, output_format):
        import os
        
        domain_name = self.domain_name.lower()
        if output_format == 'unsafe':
            filename = f"{domain_name}_{report_type}_unsafe.{file_type}"
        else:
            filename = f"{domain_name}_{report_type}.{file_type}"
        
        os.makedirs(self.report_dir, exist_ok=True)
        
        file_path = os.path.join(self.report_dir, filename)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"HTML report saved: {file_path}")
    
    def _get_username_regex(self):
        if self._username_regex is None:
            sorted_usernames = sorted(self.user_details.keys(), key=len, reverse=True)
            self._username_pattern = '|'.join(map(re.escape, sorted_usernames))
            self._username_regex = re.compile(f'(?<!\\w)({self._username_pattern})(?!\\w)', re.IGNORECASE)
        return self._username_regex
    
    def _format_user_login_line(self, match):
        username, last_login = match.groups()
        return f"{self.make_username_hoverable(username)} - Last login: {html.escape(last_login)}"

    def _format_user_password_line(self, match):
        username, password = match.groups()
        if self.output_format == 'unsafe':
            password_display = '(blank)' if password == '' else html.escape(password)
            return f"{self.make_username_hoverable(username)}: <span class='password'>{password_display}</span>"
        else:
            return f"{self.make_username_hoverable(username)}: ********"

    def read_file_content(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                return file.read()
        except FileNotFoundError:
            print(f"Warning: Required file not found: {file_path}")
            print(f"Expected location: {os.path.abspath(file_path)}")
            print("Please ensure all required files are present in the correct location.")
            return ""
        except Exception as e:
            print(f"Error reading file {file_path}: {str(e)}")
            print(f"Full path: {os.path.abspath(file_path)}")
            return ""
    
    def make_username_hoverable(self, username):
        sanitised_username = re.sub(r'\s*\(.*?\)', '', username).lower()
        user_data = self.user_details.get(sanitised_username)

        if not user_data:
            pwd_last_changed = 'Unknown'
            if sanitised_username == 'krbtgt' and self.neo4j_data:
                krbtgt_pwd = self.neo4j_data.get_krbtgt_password_last_changed()
                if krbtgt_pwd and krbtgt_pwd not in ['Unknown', 'Never', 0, -1]:
                    pwd_last_changed = krbtgt_pwd

            user_data = {
                'username': sanitised_username,
                'domain': self.domain_name.lower(),
                'description': 'No description available',
                'enabled': False,
                'isAdmin': False,
                'adminAccessReason': 'Not an admin',
                'lastLogon': 'Never',
                'passwordLastChanged': pwd_last_changed,
                'groups': [],
                'password': ''
            }
            self.user_details[sanitised_username] = user_data

        escaped_username = html.escape(username)
        escaped_key = html.escape(sanitised_username, quote=True)
        return f'<span class="hoverable-username" data-username="{escaped_key}">{escaped_username}</span>'
    
    def generate_password_statistics_content(self, password_length_data):
        content = []
        content.append('        <h2>Password Statistics</h2>')
        content.append('        <div class="section">')
        content.append('            <h2>Password Length Distribution</h2>')
        
        min_pwd_length = self.policy_analyzer.domain_properties.get('minpwdlength')
        if min_pwd_length is not None:
            content.append('            <div style="margin-bottom: 15px; padding: 10px; background-color: #f8f9fa; border-left: 4px solid #007bff; border-radius: 4px;">')
            content.append('                <div style="display: flex; align-items: center; gap: 20px; font-size: 14px;">')
            content.append('                    <div style="display: flex; align-items: center; gap: 5px;">')
            content.append('                        <div style="width: 16px; height: 16px; background-color: rgba(220, 53, 69, 0.8); border: 1px solid rgba(220, 53, 69, 1); border-radius: 2px;"></div>')
            content.append(f'                        <span>Below minimum length (&lt; {min_pwd_length} characters)</span>')
            content.append('                    </div>')
            content.append('                    <div style="display: flex; align-items: center; gap: 5px;">')
            content.append('                        <div style="width: 16px; height: 16px; background-color: rgba(54, 162, 235, 0.8); border: 1px solid rgba(54, 162, 235, 1); border-radius: 2px;"></div>')
            content.append(f'                        <span>Meets requirement (&ge; {min_pwd_length} characters)</span>')
            content.append('                    </div>')
            content.append('                </div>')
            content.append('            </div>')
        content.append('            <canvas id="lengthChart"></canvas>')
        content.append('            <div id="userListContainer" class="user-list" style="display:none;">')
        content.append('                <h4 id="userListTitle"></h4>')
        content.append('                <ul id="userList"></ul>')
        content.append('            </div>')

        chart_data = {}
        for length, users in password_length_data.items():
            chart_data[str(length)] = len(users)

        content.append(f'            <script>var chartData = {_json_for_script(chart_data)};</script>')
        
        content.append('        </div>')
        return content
    
    def ensure_likely_usernames(self):
        if self.likely_usernames is None or len(self.likely_usernames) == 0:
            print("Fetching statistically likely usernames...")
            self.likely_usernames = get_likely_usernames()
