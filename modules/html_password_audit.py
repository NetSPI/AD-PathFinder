import re
import html


class PasswordAuditMixin:
    def generate_password_audit_content(self, report_data):
        content = []

        group_membership_tooltip = (
            "<b>User is a direct or nested member of privileged group(s) including:</b><br><br>"
            "• Domain Admins<br>"
            "• Account Operators<br>"
            "• Enterprise Admins<br>"
            "• Administrators<br>"
            "• Domain Controllers<br>"
            "• Server Operators<br>"
            "• Backup Operators<br>"
            "• Print Operators<br>"
            "• Schema Admins<br>"
            "• DnsAdmins<br>"
            "• Exchange Organization Administrators<br>"
            "• Exchange Trusted Subsystem<br>"
            "• Key Admins<br>"
            "• Enterprise Key Admins<br>"
            "• Certificate Admins<br>"
            "• Group Policy Creator Owners<br>"
            "• Cryptographic Operators<br>"
            "• Hyper-V Administrators<br>"
            "• Access Control Assistance Operators"
        )

        content.append('        <h2>Password Audit Results</h2>')
        content.append('        <div class="section">')
        content.append('            <h2>Account Statistics</h2>')
        content.append('            <div class="chart-container">')
        content.append('                <div class="chart">')
        content.append('                    <canvas id="userChart"></canvas>')
        content.append('                </div>')
        content.append('                <div class="chart">')
        content.append('                    <canvas id="computerChart"></canvas>')
        content.append('                </div>')
        content.append('            </div>')
        content.append('        </div>')

        current_section_div_id = None
        current_section_ul_id = None
        shared_password_groups = []
        current_shared_group_dict = None
        in_shared_passwords_section = False
        user_line_regex = re.compile(r"^\s+([^-].*?)\s*(?:-\s*Last login:.*)?$")

        for line_num, line in enumerate(report_data.split('\n')):
            original_line = line
            line = line.strip()
            if line == '':
                continue

            new_section_detected = False
            section_header_html = None
            new_current_section_name = None
            new_section_ul_id = None
            new_section_div_id = None

            if line.startswith("Users with passwords containing 'lm hash configured':"):
                new_section_detected = True
                new_current_section_name = 'lm_hash'
                count = line.split(':')[-1].strip()
                section_header_html = f'        <h2>Users Configured with LM Hash: {count}</h2>'
            elif line.startswith('Cracked Admin Accounts (Group Membership):'):
                new_section_detected = True
                new_current_section_name = 'cracked_admins'
                count = line.split(':')[-1].strip()
                tooltip_html = self._create_hoverable_tooltip_span("(Group Membership)", group_membership_tooltip, style="color: inherit; text-decoration: none; cursor: help")
                section_header_html = f'        <h2>Cracked Admin Accounts {tooltip_html}: {count}</h2>'
            elif line.startswith('Cracked Computer Accounts:'):
                new_section_detected = True
                new_current_section_name = 'cracked_computers'
                count = line.split(':')[-1].strip()
                section_header_html = f'        <h2>Cracked Computer Accounts: {count}</h2>'
            elif line.startswith("Users with passwords containing '"):
                match = re.match(r"Users with passwords containing '(.*)': (\d+)", line)
                if match:
                    new_section_detected = True
                    new_current_section_name = 'category_accounts'
                    category_name = html.escape(match.group(1))
                    count = match.group(2)
                    section_header_html = f'        <h2>Users with passwords containing \'{category_name}\': {count}</h2>'
            elif line.startswith('Users with Cracked Passwords:'):
                new_section_detected = True
                new_current_section_name = 'weak_passwords'
                count = line.split(':')[-1].strip()
                section_header_html = f'        <h2>Users with Cracked Passwords: {count}</h2>'
            elif line.startswith('Account with Shared Password:'):
                new_section_detected = True
                new_current_section_name = 'shared_passwords'
                if current_section_ul_id: content.append('        </ul>')
                if current_section_div_id: content.append('    </div>')
                new_section_div_id = "shared-password-section"
                new_section_ul_id = "shared-password-list"
                content.append(f'    <div class="section" id="{new_section_div_id}">')
                content.append('        <h2>Accounts with Shared Passwords</h2>')
                content.append(f'        <ul id="{new_section_ul_id}">')
                in_shared_passwords_section = True
                shared_password_groups = []
                current_shared_group_dict = None
                current_section_div_id = new_section_div_id
                current_section_ul_id = new_section_ul_id
                continue

            if new_section_detected and new_current_section_name != 'shared_passwords':
                if current_section_ul_id: content.append('        </ul>')
                if current_section_div_id: content.append('    </div>')

                new_section_div_id = f"{new_current_section_name}-section"
                new_section_ul_id = f"{new_current_section_name}-list"
                content.append(f'    <div class="section" id="{new_section_div_id}">')
                content.append(section_header_html)
                content.append(f'        <ul id="{new_section_ul_id}">')
                in_shared_passwords_section = False
                current_shared_group_dict = None
                current_section_div_id = new_section_div_id
                current_section_ul_id = new_section_ul_id
                continue

            if in_shared_passwords_section:
                header_match = re.match(r"^\(Occurrences: (\d+)\)$", line)
                unsafe_header_match = re.match(r"^(.+?)\s+\(Occurrences: (\d+)\)\s+-\s+Password:\s+(.+)$", line)

                if header_match:
                    occurrences = int(header_match.group(1))
                    new_group = {
                        'hash': '[REDACTED]',
                        'occurrences': occurrences,
                        'password': '********',
                        'users': []
                    }
                    shared_password_groups.append(new_group)
                    current_shared_group_dict = new_group
                    continue
                elif unsafe_header_match:
                    hash_value = unsafe_header_match.group(1).strip()
                    occurrences = int(unsafe_header_match.group(2))
                    password_value = unsafe_header_match.group(3).strip()

                    new_group = {
                        'hash': hash_value,
                        'occurrences': occurrences,
                        'password': password_value,
                        'users': []
                    }
                    shared_password_groups.append(new_group)
                    current_shared_group_dict = new_group
                    continue

                user_match = user_line_regex.match(original_line)
                if user_match and current_shared_group_dict is not None:
                    username = user_match.group(1).strip()
                    username = re.sub(r'\s*\((admin|disabled)\)$', '', username, flags=re.IGNORECASE).strip()
                    if username:
                        current_shared_group_dict['users'].append((username, None))
                    continue
                if line.startswith('No accounts with shared passwords found.'):
                    current_shared_group_dict = None
                    continue

                if line:
                    current_shared_group_dict = None

            elif current_section_ul_id:
                if original_line.startswith('\t') or original_line.startswith('    - ') or original_line.startswith('    '):
                    line_content = line
                    if not line_content.startswith('No users') and line_content:
                        formatted_content = self.format_line_for_html(line_content.replace('- ', '', 1))
                        content.append(f'            <li>{formatted_content}</li>')
                        continue

        if shared_password_groups:
            shared_list_items_html = []
            for i, group_data in enumerate(shared_password_groups, 1):
                occurrences = group_data['occurrences']
                users = group_data['users']
                password_text = group_data.get('password', '')
                is_uncracked = password_text == 'Not cracked'
                group_class = 'shared-group shared-group-uncracked' if is_uncracked else 'shared-group'

                shared_list_items_html.append(f'            <div class="{group_class}">')
                header_suffix = ' <span class="uncracked-badge">Not cracked</span>' if is_uncracked else ''
                shared_list_items_html.append(f'                <h3>Group {i} ({occurrences} accounts){header_suffix}</h3>')

                if self.output_format == 'unsafe':
                    hash_text = group_data['hash']
                    display_password = '(blank)'
                    if password_text.strip() != '' and password_text != '********' and password_text != '(blank)':
                        display_password = html.escape(password_text)

                    shared_list_items_html.append(f'                <p><b>- Hash:</b> {html.escape(hash_text)} - <b>Password:</b> <span class="password">{display_password}</span></p>')

                if users:
                    shared_list_items_html.append('                <ul>')
                    sorted_users = sorted(users, key=lambda u: u[0].lower())
                    for username, _ in sorted_users:
                        shared_list_items_html.append(f'                    <li>{self.make_username_hoverable(username)}</li>')
                    shared_list_items_html.append('                </ul>')
                else:
                    shared_list_items_html.append('                <p><i>No users listed for this group in the parsed report data.</i></p>')

                shared_list_items_html.append(f'            </div>')
            list_start_index = -1
            for i, html_line in enumerate(content):
                if f'<ul id="{current_section_ul_id}">' in html_line and current_section_ul_id == "shared-password-list":
                    list_start_index = i
                    break

            if list_start_index != -1:
                content = content[:list_start_index+1] + shared_list_items_html + content[list_start_index+1:]
                ul_closed = any('</ul>' in l for l in content[list_start_index+1+len(shared_list_items_html):])
                div_closed = any('</div>' in l for l in content[list_start_index+1+len(shared_list_items_html):])

                if not ul_closed: content.append('        </ul>')
                if not div_closed: content.append('    </div>')
            else:
                content.extend(shared_list_items_html)
                if shared_list_items_html:
                    content.append('        </ul>')
                    content.append('    </div>')

        elif in_shared_passwords_section:
            list_start_index = -1
            for i, html_line in enumerate(content):
                if f'<ul id="{current_section_ul_id}">' in html_line and current_section_ul_id == "shared-password-list":
                    list_start_index = i
                    break
            if list_start_index != -1:
                content.insert(list_start_index + 1, '            <li>No accounts with shared passwords found.</li>')
                if content[-1].strip() != '</ul>': content.append('        </ul>')
                if content[-1].strip() != '</div>': content.append('    </div>')

        if current_section_ul_id and (not content or content[-1].strip() != '</ul>'):
            if any(f'<ul id="{current_section_ul_id}">' in line for line in content):
                content.append('        </ul>')
        if current_section_div_id and (not content or content[-1].strip() != '</div>'):
            if any(f'<div class="section" id="{current_section_div_id}">' in line for line in content):
                content.append('    </div>')

        return content
