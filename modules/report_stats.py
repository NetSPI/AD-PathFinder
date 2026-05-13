import re
from .utils import find_cracked_accounts


class ReportStatsMixin:
    def _gather_password_statistics(self):
        password_statistics = {}

        if not hasattr(self, 'analysis') or not self.analysis:
            return password_statistics

        try:
            all_user_data = self.account_analysis.get_all_user_data()
            statistics_report = self.analysis.generate_detailed_statistics(
                self.analysis.cracked_hashes,
                self.analysis.ntds_hashes,
                all_user_data
            )

            stats = self._parse_statistics_report(statistics_report)

            password_statistics["user_analysis"] = {
                "total_users": stats.get("total_users", 0),
                "enabled_users": stats.get("enabled_users", 0),
                "disabled_users": stats.get("disabled_users", 0),
                "cracked_users": stats.get("cracked_users", 0),
                "enabled_users_pct": stats.get("enabled_users_pct", 0),
                "disabled_users_pct": stats.get("disabled_users_pct", 0),
                "cracked_users_pct": stats.get("cracked_users_pct", 0)
            }

            password_statistics["computer_analysis"] = {
                "total_computers": stats.get("total_computers", 0),
                "enabled_computers": stats.get("enabled_computers", 0),
                "disabled_computers": stats.get("disabled_computers", 0),
                "cracked_computers": stats.get("cracked_computers", 0),
                "enabled_computers_pct": stats.get("enabled_computers_pct", 0),
                "disabled_computers_pct": stats.get("disabled_computers_pct", 0),
                "cracked_computers_pct": stats.get("cracked_computers_pct", 0)
            }

            if hasattr(self.analysis, 'category_details') and self.analysis.category_details:
                category_data = {}

                for category_name, details in self.analysis.category_details.items():
                    users_list = []

                    for user_entry in details.get("users", []):
                        username = user_entry.split(":")[0] if ":" in user_entry else user_entry
                        users_list.append(username)

                    category_data[category_name] = sorted(users_list)

                password_statistics["password_categories"] = category_data
            else:
                password_statistics["password_categories"] = {}

            admin_accounts = []
            privileged_accounts = []

            if hasattr(self.analysis, 'cracked_enabled_admin_users'):
                for user_entry in self.analysis.cracked_enabled_admin_users:
                    username = user_entry.split(":")[0] if ":" in user_entry else user_entry
                    admin_accounts.append(username)

            if hasattr(self.analysis, 'cracked_enabled_privileged_users'):
                for user_entry in self.analysis.cracked_enabled_privileged_users:
                    username = user_entry.split(":")[0] if ":" in user_entry else user_entry
                    privileged_accounts.append(username)

            password_statistics["cracked_admin_accounts"] = sorted(admin_accounts)
            password_statistics["cracked_privileged_accounts"] = sorted(privileged_accounts)

            weak_password_users = {}
            if hasattr(self.analysis, 'active_usernames'):
                cracked_accounts = find_cracked_accounts(
                    self.analysis.cracked_hashes,
                    self.analysis.ntlmv2_hashes,
                    self.analysis.ntds_hashes
                )

                for username, password in cracked_accounts.items():
                    if username.lower() in self.analysis.active_usernames:
                        username_clean = username
                        weak_password_users[username_clean] = username_clean

            password_statistics["all_cracked_accounts"] = sorted(list(weak_password_users.keys()))

        except Exception as e:
            print(f"Warning: Error gathering password statistics: {e}")

        return password_statistics

    def _parse_statistics_report(self, report_text):
        stats = {}
        
        try:
            lines = report_text.split('\n')
            for line in lines:
                line = line.strip()
                
                if "Total User Accounts:" in line:
                    stats["total_users"] = int(line.split(":")[1].strip())
                elif "Enabled User Accounts:" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        count_part = parts[1].split("(")[0].strip()
                        stats["enabled_users"] = int(count_part)
                        
                        pct_match = re.search(r"\(([\d\.]+)%", line)
                        if pct_match:
                            stats["enabled_users_pct"] = float(pct_match.group(1))
                elif "Disabled User Accounts:" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        count_part = parts[1].split("(")[0].strip()
                        stats["disabled_users"] = int(count_part)
                        
                        pct_match = re.search(r"\(([\d\.]+)%", line)
                        if pct_match:
                            stats["disabled_users_pct"] = float(pct_match.group(1))
                elif "Total Cracked User Accounts:" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        count_part = parts[1].split("(")[0].strip()
                        stats["cracked_users"] = int(count_part)
                        
                        pct_match = re.search(r"\(([\d\.]+)%", line)
                        if pct_match:
                            stats["cracked_users_pct"] = float(pct_match.group(1))
                
                elif "Total Computer Accounts:" in line:
                    stats["total_computers"] = int(line.split(":")[1].strip())
                elif "Enabled Computer Accounts:" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        count_part = parts[1].split("(")[0].strip()
                        stats["enabled_computers"] = int(count_part)

                        pct_match = re.search(r"\(([\d\.]+)%", line)
                        if pct_match:
                            stats["enabled_computers_pct"] = float(pct_match.group(1))
                elif "Disabled Computer Accounts:" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        count_part = parts[1].split("(")[0].strip()
                        stats["disabled_computers"] = int(count_part)
                        
                        pct_match = re.search(r"\(([\d\.]+)%", line)
                        if pct_match:
                            stats["disabled_computers_pct"] = float(pct_match.group(1))
                elif "Total Cracked Computer Accounts:" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        count_part = parts[1].split("(")[0].strip()
                        stats["cracked_computers"] = int(count_part)
                        
                        pct_match = re.search(r"\(([\d\.]+)%", line)
                        if pct_match:
                            stats["cracked_computers_pct"] = float(pct_match.group(1))
            
            if "total_computers" in stats and "disabled_computers" in stats and "enabled_computers" not in stats:
                stats["enabled_computers"] = stats["total_computers"] - stats["disabled_computers"]

        except ValueError:
            pass

        return stats

    def get_user_details(self, report_data):
        if hasattr(self, '_fetched_user_details') and self._fetched_user_details:
            return
        self._fetched_user_details = True

        all_user_data = self.account_analysis.get_all_user_data()
        cracked_accounts = find_cracked_accounts(self.cracked_hashes, self.ntlmv2_hashes, self.ntds_hashes)

        self.user_details = {}

        for user in all_user_data:
            if user is None or not user.get('username'):
                continue

            username_key = user['username'].lower()
            username_with_domain = user.get('username_with_domain') or ''

            if '@' in username_with_domain:
                domain = username_with_domain.split('@')[1].lower()
            elif '.' in username_with_domain:
                domain = '.'.join(username_with_domain.split('.')[1:]).lower()
            else:
                domain = self.domain_name.lower()

            self.user_details[username_key] = {
                'username': user['username'],
                'domain': domain,
                'description': user.get('description', 'No description available'),
                'groups': user.get('groups', []),
                'enabled': user.get('enabled', False),
                'isAdmin': user.get('isAdmin', False),
                'isPrivileged': user.get('isPrivileged', False),
                'adminAccessReason': 'Group Membership' if user.get('isAdmin') else '',
                'lastLogon': user.get('lastLogon', 'Never'),
                'passwordLastChanged': user.get('passwordLastChanged', 'Unknown'),
                'password': cracked_accounts.get(username_key),
                'asrepRoastable': user.get('asrepRoastable', False),
                'kerberoastable': user.get('kerberoastable', False),
            }
                            
    def parse_report_statistics(self, report_data):
        stats = {
            "total_users": 0,
            "enabled_users": 0,
            "disabled_users": 0,
            "cracked_users": 0,
            "total_computers": 0,
            "enabled_computers": 0,
            "disabled_computers": 0,
            "cracked_computers": 0
        }

        for line in report_data.split('\n'):
            if "Total User Accounts:" in line:
                stats["total_users"] = int(line.split(":")[1].strip())
            elif "Enabled User Accounts:" in line:
                stats["enabled_users"] = int(line.split(":")[1].split("(")[0].strip())
            elif "Disabled User Accounts:" in line:
                stats["disabled_users"] = int(line.split(":")[1].split("(")[0].strip())
            elif "Total Cracked User Accounts:" in line:
                stats["cracked_users"] = int(line.split(":")[1].split("(")[0].strip())
            elif "Total Computer Accounts:" in line:
                stats["total_computers"] = int(line.split(":")[1].strip())
            elif "Enabled Computer Accounts:" in line:
                stats["enabled_computers"] = int(line.split(":")[1].split("(")[0].strip())
            elif "Disabled Computer Accounts:" in line:
                stats["disabled_computers"] = int(line.split(":")[1].split("(")[0].strip())
            elif "Total Cracked Computer Accounts:" in line:
                stats["cracked_computers"] = int(line.split(":")[1].split("(")[0].strip())

        if "enabled_computers" not in stats:
            stats["enabled_computers"] = stats["total_computers"] - stats["disabled_computers"]

        return stats
