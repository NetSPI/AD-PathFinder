import re
from .utils import find_cracked_accounts, base_form

class Analysis:
    def __init__(self, neo4j_data, cracked_hashes, ntlmv2_hashes, ntds_hashes, account_analysis=None):
        self.neo4j_data = neo4j_data
        self.cracked_hashes = cracked_hashes
        self.ntlmv2_hashes = ntlmv2_hashes
        self.ntds_hashes = ntds_hashes
        self.account_analysis = account_analysis
        self.password_length_data = {}
            
    def password_audit(self, company_names=None, output_format='safe'):
        if hasattr(self, 'account_analysis') and self.account_analysis:
            all_user_data = self.account_analysis.get_all_user_data()
        else:
            skip_high_value = self.ntds_hashes is None
            all_user_data = self.neo4j_data.get_all_users_with_attributes(skip_high_value=skip_high_value)

        all_user_data, active_usernames = self._fetch_user_data(all_user_data)
        self.active_usernames = active_usernames

        statistics_report = self.generate_detailed_statistics(self.cracked_hashes, self.ntds_hashes, all_user_data)

        if self.ntds_hashes is None or self.cracked_hashes is None:
            print("NTDS data or cracked hashes data not available. Skipping detailed password analysis.")
            return statistics_report

        category_patterns = self._define_category_patterns(company_names)

        (total_enabled_cracked_users, category_details,
         cracked_enabled_admin_users, cracked_enabled_privileged_users,
         password_length_data, password_complexity_data) = self._analyse_passwords(
            self.cracked_hashes, self.ntds_hashes, active_usernames,
            category_patterns, output_format, all_user_data
        )

        self.password_length_data = password_length_data
        self.password_complexity_data = password_complexity_data
        self.category_details = category_details
        self.cracked_enabled_admin_users = cracked_enabled_admin_users
        self.cracked_enabled_privileged_users = cracked_enabled_privileged_users

        analysis_report = self._output_analysis_results(
            total_enabled_users=len(active_usernames),
            total_enabled_cracked_users=total_enabled_cracked_users,
            category_details=category_details,
            cracked_enabled_admin_users=cracked_enabled_admin_users,
            cracked_enabled_privileged_users=cracked_enabled_privileged_users,
            output_format=output_format
        )

        combined_report = f"{statistics_report}\n{analysis_report}"

        return combined_report

    def _fetch_user_data(self, all_user_data):
        active_usernames = {user['username'].lower() for user in all_user_data if user.get('username') and user.get('enabled')}
        return all_user_data, active_usernames

    def _define_category_patterns(self, company_names):
        substitutions = {
            '@': 'a', '0': 'o', '$': 's', '3': 'e', '1': 'i', '4': 'a',
            '5': 's', '7': 't', '8': 'b', '9': 'g', '!': 'i', '+': 't',
            '&': 'a', '^': 'a', '*': 'a', '#': 'h'
        }
        password_pattern = re.compile(
            r'p[a@4]s{1,2}[w\s]*[o0@]r?d[s]?\d*[!@#$%^&*]?',
            re.IGNORECASE
        )
        welcome_pattern = re.compile(
            r'w[e3][l1!][c]?[o0][m][e3]\d*[!@#$%^&*]?',
            re.IGNORECASE
        )
        season_patterns = [
            re.compile(
                r'\b(spring|summer|fall|autumn|winter)'
                r'[_\s]?\d*[!@#$%^&*]?\b', 
                re.IGNORECASE
            )
        ]
        day_patterns = [
            re.compile(
                r'\b(mon|tue(?:s)?|wed(?:nes)?|thu(?:rs)?|fri|sat(?:ur)?|sun)'
                r'[_\s]?(?:day)?\d*[!@#$%^&*]?\b', 
                re.IGNORECASE
            )
        ]
        month_patterns = [
            re.compile(
                r'\b(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|'
                r'jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|'
                r'dec(?:ember)?)[_\s]?\d*[!@#$%^&*]?\b', 
                re.IGNORECASE
            )
        ]
        company_patterns = []
        if company_names:
            for company_name in company_names:
                pattern = rf'{re.escape(company_name)}\d*[!@#$%^&*]*\b'
                compiled_pattern = re.compile(pattern, re.IGNORECASE)
                company_patterns.append(compiled_pattern)
        else:
            company_patterns = None

        blank_password_pattern = re.compile(r'^$')
    
        return  {
            "blank password": blank_password_pattern,
            "password": password_pattern,
            "welcome": welcome_pattern,
            "season of the year": season_patterns,
            "day of week": day_patterns,
            "month of year": month_patterns,
            "company name": company_patterns,
            "cracked computer account": None
        }

    def _analyse_passwords(self, cracked_hashes, ntds_hashes, active_usernames, category_patterns, output_format, all_user_data=None):
        if not ntds_hashes or not cracked_hashes:
            print("NTDS data or cracked hashes data not available. Skipping password analysis.")
            return 0, {}, [], [], {}, {}

        BLANK_HASH = '31D6CFE0D16AE931B73C59D7E0C089C0'
        DEFAULT_LM_HASH = 'aad3b435b51404eeaad3b435b51404ee'

        cracked_accounts = find_cracked_accounts(cracked_hashes, self.ntlmv2_hashes, ntds_hashes)
        total_enabled_cracked_users = 0
        cracked_enabled_admin_users = []
        cracked_enabled_privileged_users = []

        category_details = {category: {"pattern": pattern, "users": []} for category, pattern in category_patterns.items()}
        category_details["username similarity"] = {"pattern": None, "users": []}
        category_details["lm hash configured"] = {"pattern": None, "users": []}
        category_details["cracked computer account"] = {"pattern": None, "users": []}

        password_length_data = {}
        password_complexity_data = {}

        admin_usernames = set()
        privileged_usernames = set()
        
        for user in all_user_data:
            if not user.get('username'):
                continue
            username = user['username'].lower()
            if user.get('isAdmin'):
                admin_usernames.add(username)
            elif user.get('isPrivileged'):
                privileged_usernames.add(username)

        _, lm_hashes = self.ntds_hashes

        for username_lower, lm_hash in lm_hashes.items():
            if username_lower in active_usernames and lm_hash != DEFAULT_LM_HASH:
                if output_format == 'unsafe' and username_lower in cracked_accounts:
                    user_info = f"{username_lower}:{cracked_accounts[username_lower]}"
                else:
                    user_info = username_lower
                category_details["lm hash configured"]["users"].append(user_info)

        for username, password in cracked_accounts.items():
            if username.lower() in active_usernames:
                total_enabled_cracked_users += 1

                if password == BLANK_HASH:
                    password = ''
        
                password_base = base_form(password)
                user_info = f"{username}:{password}" if output_format == 'unsafe' else username
        
                username_lower = username.lower()
                if username_lower in admin_usernames:
                    cracked_enabled_admin_users.append(user_info)
                elif username_lower in privileged_usernames:
                    cracked_enabled_privileged_users.append(user_info)
        
                pwd_length = len(password)
                formatted_user_info = username if output_format == 'safe' else user_info
                password_length_data.setdefault(str(pwd_length), []).append(formatted_user_info)
        
                complexity = sum([
                    any(c.islower() for c in password),
                    any(c.isupper() for c in password),
                    any(c.isdigit() for c in password),
                    any(c in "!@#$%^&*()-_=+[]{}|;:',.<>/?`~" for c in password)
                ])
                password_complexity_data.setdefault(complexity, []).append(formatted_user_info)
        
                user_data = next((u for u in all_user_data if (u.get('username') or '').lower() == username.lower()), None)
                if user_data and 'domain computers' in user_data.get('groups', []):
                    category_details["cracked computer account"]["users"].append(user_info)

                categorised = False
                for category, details in category_details.items():
                    if category == "username similarity" or category == "lm hash configured" or category == "cracked computer account":
                        continue
                        
                    patterns = details["pattern"]
                    if patterns is None:
                        continue
                        
                    if not isinstance(patterns, list):
                        patterns = [patterns]
                    
                    for pattern in patterns:
                        if pattern.search(password) or pattern.search(password_base):
                            details["users"].append(user_info)
                            categorised = True
                            break
                    
                    if categorised:
                        break
        
                if self.is_password_similar_to_username(username, password):
                    category_details["username similarity"]["users"].append(user_info)
                    categorised = True
    
        return (total_enabled_cracked_users, category_details, cracked_enabled_admin_users, 
                cracked_enabled_privileged_users, password_length_data, password_complexity_data)
        
    def is_password_similar_to_username(self, username, password):        
        username_lower = username.lower()
        password_lower = password.lower()
        
        if username_lower in password_lower:
            return True
        
        if password_lower.startswith(username_lower):
            return True
        
        username_pattern = re.compile(rf'^{re.escape(username_lower)}[0-9!@#$%^&*()-_=+\[\]{{}}|;:\'",.<>/?`~]*$')
        if username_pattern.match(password_lower):
            return True
        
        if username_lower[::-1] in password_lower:
            return True
        
        leet_speak_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
        leet_username = ''.join(leet_speak_map.get(c, c) for c in username_lower)
        if leet_username in password_lower:
            return True
        
        return False
    
    def _output_analysis_results(self, total_enabled_users, total_enabled_cracked_users, category_details, 
                               cracked_enabled_admin_users, cracked_enabled_privileged_users, output_format='safe'):
        report_lines = []
    
        if output_format == "back":
            return
    
        def format_user_info(user_info, format_type):
            username = user_info.split(":", 1)[0]
            if format_type == "safe":
                return username
            else:
                return user_info
    
        if cracked_enabled_admin_users:
            admin_count = len(cracked_enabled_admin_users)
            report_lines.append(f"\nCracked Admin Accounts (Group Membership): {admin_count}")
            sorted_admin_users = sorted(cracked_enabled_admin_users, key=lambda x: x.lower())
            for admin_user in sorted_admin_users:
                report_lines.append(f"\t{format_user_info(admin_user, output_format)}")

        if cracked_enabled_privileged_users:
            privileged_count = len(cracked_enabled_privileged_users)
            report_lines.append(f"\nCracked Privileged Accounts (Indirect Access): {privileged_count}")
            sorted_privileged_users = sorted(cracked_enabled_privileged_users, key=lambda x: x.lower())
            for privileged_user in sorted_privileged_users:
                report_lines.append(f"\t{format_user_info(privileged_user, output_format)}")
    
        for category, details in category_details.items():
            if not details['users']:
                continue
            if category == "cracked computer account":
                report_lines.append(f"\nCracked Computer Accounts: {len(details['users'])}")
            else:
                report_lines.append(f"\nUsers with passwords containing '{category}': {len(details['users'])}")
            sorted_users = sorted(details['users'], key=lambda x: x.lower())
            for user in sorted_users:
                report_lines.append(f"\t{format_user_info(user, output_format)}")
    
        weak_password_users = {}
        cracked_accounts = find_cracked_accounts(self.cracked_hashes, self.ntlmv2_hashes, self.ntds_hashes)
        for username, password in cracked_accounts.items():
            if username.lower() in self.active_usernames:
                if output_format == 'unsafe':
                    user_info = f"{username}:{password}"
                else:
                    user_info = f"{username}"
                weak_password_users[username] = user_info
    
        weak_password_count = len(weak_password_users)
        report_lines.append(f"\nUsers with Cracked Passwords: {weak_password_count}")
        if weak_password_users:
            sorted_weak_users = sorted(weak_password_users.values(), key=lambda x: x.lower())
            for user_info in sorted_weak_users:
                report_lines.append(f"\t{user_info}")
    
        report_string = "\n".join(report_lines)
        return report_string
    
    def generate_detailed_statistics(self, cracked_hashes, ntds_hashes, all_user_data):
        cracked_accounts = find_cracked_accounts(cracked_hashes, self.ntlmv2_hashes, ntds_hashes)

        total_users = 0
        total_computers = 0
        disabled_users = 0
        disabled_computers = 0
        total_cracked_users = 0
        total_cracked_computers = 0
    
        for user in all_user_data:
            username_lower = (user.get('username') or '').lower()
            if not username_lower:
                continue
            
            is_computer = bool(user.get('is_computer')) or 'domain computers' in (user.get('groups') or [])
            is_enabled = user['enabled']
            is_cracked = username_lower in cracked_accounts
    
            if is_computer:
                total_computers += 1
                if not is_enabled:
                    disabled_computers += 1
                if is_enabled and is_cracked:
                    total_cracked_computers += 1
            else:
                total_users += 1
                if not is_enabled:
                    disabled_users += 1
                if is_enabled and is_cracked:
                    total_cracked_users += 1


        enabled_users = total_users - disabled_users
        enabled_computers = total_computers - disabled_computers
        enabled_users_percentage = (enabled_users / total_users) * 100 if total_users else 0
        disabled_users_percentage = (disabled_users / total_users) * 100 if total_users else 0
        enabled_computers_percentage = (enabled_computers / total_computers) * 100 if total_computers else 0
        disabled_computers_percentage = (disabled_computers / total_computers) * 100 if total_computers else 0
        cracked_users_percentage = (total_cracked_users / enabled_users) * 100 if enabled_users else 0
        cracked_computers_percentage = (total_cracked_computers / enabled_computers) * 100 if enabled_computers else 0

        statistics_report = (
            "User Analysis\n\n"
            f"Total User Accounts: {total_users}\n"
            f"Enabled User Accounts: {enabled_users} ({enabled_users_percentage:.2f}% of total users)\n"
            f"Disabled User Accounts: {disabled_users} ({disabled_users_percentage:.2f}% of total users)\n"
            f"Total Cracked User Accounts: {total_cracked_users} ({cracked_users_percentage:.2f}% of enabled users)\n"
            "\nComputer Analysis\n\n"
            f"Total Computer Accounts: {total_computers}\n"
            f"Enabled Computer Accounts: {enabled_computers} ({enabled_computers_percentage:.2f}% of total computers)\n"
            f"Disabled Computer Accounts: {disabled_computers} ({disabled_computers_percentage:.2f}% of total computers)\n"
            f"Total Cracked Computer Accounts: {total_cracked_computers} ({cracked_computers_percentage:.2f}% of enabled computers)\n"
        )
    
        return statistics_report