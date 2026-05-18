class PolicyComplianceAnalyzer:
    def __init__(self, neo4j_data, cracked_accounts, user_details, domain_name, category_details=None, likely_usernames=None):
        self.neo4j_data = neo4j_data
        self.cracked_accounts = cracked_accounts
        self.user_details = user_details
        self.domain_name = domain_name
        self.category_details = category_details or {}
        self.likely_usernames = likely_usernames or []
        self.violations_cache = {}
        self.domain_properties = {}
        self.fetch_domain_properties()
    
    def fetch_domain_properties(self):
        self.domain_properties = (
            self.neo4j_data.get_domain_properties_filtered() if self.neo4j_data else {}
        )
    
    def analyze_user_violations(self, username):
        if username in self.violations_cache:
            return self.violations_cache[username]
        
        violations = []
        user_data = self.user_details.get(username.lower(), {})
        
        for category, category_data in self.category_details.items():
            # Skip the cracked computer account category - it's not a predictable pattern
            if category == 'cracked computer account':
                continue
                
            if isinstance(category_data, dict) and 'users' in category_data:
                usernames = category_data['users']
            else:
                usernames = category_data
            
            username_found = False
            for user_entry in usernames:
                if isinstance(user_entry, str) and ':' in user_entry:
                    entry_username = user_entry.split(':', 1)[0]
                else:
                    entry_username = user_entry
                
                if username == entry_username:
                    username_found = True
                    break
            
            if username_found:
                violations.append({
                    'type': 'pattern',
                    'message': self._get_pattern_message(category),
                    'pattern_type': category.replace(' ', '_'),
                    'pattern_text': category
                })
        
        if user_data.get('isAdmin', False):
            violations.append({
                'type': 'admin_account',
                'message': 'Admin Account with Weak Password',
                'pattern_type': 'admin_account',
                'pattern_text': 'Cracked Admin Accounts (Group Membership):'
            })
        
        if user_data.get('isPrivileged', False):
            violations.append({
                'type': 'privileged_account',
                'message': 'Privileged Account with Weak Password',
                'pattern_type': 'privileged_account',
                'pattern_text': 'Cracked Privileged Accounts (Indirect Access):'
            })
        
        if user_data.get('kerberoastable', False):
            violations.append({
                'type': 'kerberoastable_account',
                'message': 'Kerberoastable Account with Weak Password',
                'pattern_type': 'kerberoastable_account',
                'pattern_text': 'Kerberoastable Accounts'
            })
        
        if user_data.get('asrepRoastable', False):
            violations.append({
                'type': 'asrep_roastable_account',
                'message': 'AS-REP Roastable Account with Weak Password',
                'pattern_type': 'asrep_roastable_account', 
                'pattern_text': 'AS-REP Roastable Accounts'
            })
        
        if username in self.likely_usernames:
            violations.append({
                'type': 'likely_username',
                'message': 'Statistically Likely Username',
                'pattern_type': 'likely_username',
                'pattern_text': 'Statistically Likely Usernames'
            })
        
        violations.extend(self._check_domain_policy_violations(username, user_data))
        
        self.violations_cache[username] = violations
        return violations
    
    def _check_domain_policy_violations(self, username, user_data):
        violations = []
        
        length_violation = self._check_password_length(username)
        if length_violation:
            violations.append(length_violation)
        
        return violations
    
    
    def _check_password_length(self, username):
        if 'minpwdlength' not in self.domain_properties or username not in self.cracked_accounts:
            return None

        min_length = int(self.domain_properties['minpwdlength'])

        if min_length <= 0:
            return None
            
        password = self.cracked_accounts.get(username, '')
        pwd_length = len(password)
        
        if pwd_length < min_length:
            return {'type': 'length', 'message': 'Below Min Length'}
        
        return None
    
    def _get_pattern_message(self, category):
        pattern_messages = {
            'blank password': 'Uses Blank/Empty Password',
            'password': 'Contains Variation of "Password"',
            'welcome': 'Contains Variation of "Welcome"',
            'season of the year': 'Contains Season Name (Summer, Winter, etc.)',
            'month of year': 'Contains Month Name (January, March, etc.)',
            'day of week': 'Contains Day Name (Monday, Friday, etc.)',
            'username similarity': 'Password Similar to Username',
            'company name': 'Contains Company/Organization Name',
            'lm hash configured': 'LM Hash Authentication Enabled',
            'cracked computer account': 'Computer Account with Weak Password'
        }
        return pattern_messages.get(category, f'Contains {category.title()}')
    
    def get_compliance_statistics(self):
        stats = {
            'total_cracked': 0,
            'length_violations': 0,
            'pattern_violations': 0,
            'privileged_violations': 0,
            'total_with_violations': 0
        }

        users_with_violations = set()

        for username in self.cracked_accounts:
            # Skip disabled users - only count enabled accounts in statistics
            username_lower = username.lower()
            user_data = self.user_details.get(username_lower, {})
            if not user_data.get('enabled', False):
                continue

            stats['total_cracked'] += 1

            violations = self.analyze_user_violations(username)
            if violations:
                users_with_violations.add(username)
                for violation in violations:
                    violation_type = violation['type']
                    if violation_type == 'length':
                        stats['length_violations'] += 1
                    elif violation_type == 'pattern':
                        # Exclude LM hash and computer account patterns from the pattern violations count
                        pattern_type = violation.get('pattern_type', '')
                        if pattern_type not in ['lm_hash_configured', 'cracked_computer_account']:
                            stats['pattern_violations'] += 1
                    elif violation_type in ['admin_account', 'privileged_account']:
                        stats['privileged_violations'] += 1
                    elif violation_type in ['kerberoastable_account', 'asrep_roastable_account', 'likely_username']:
                        # Count these as additional violations but don't create separate stats for them yet
                        pass

        stats['total_with_violations'] = len(users_with_violations)

        return stats
    
    def get_violation_distribution(self):
        distribution = {
            'by_type': {
                'Length Violations': 0,
                'Complexity': 0,
                'Pattern Issues': 0
            }
        }

        type_mapping = {
            'length': 'Length Violations',
            'complexity': 'Complexity',
            'pattern': 'Pattern Issues'
        }

        for username in self.cracked_accounts:
            # Skip disabled users - only count enabled accounts in distribution
            username_lower = username.lower()
            user_data = self.user_details.get(username_lower, {})
            if not user_data.get('enabled', False):
                continue

            violations = self.analyze_user_violations(username)
            for violation in violations:
                # Skip computer account and LM hash patterns from Pattern Issues count
                if violation['type'] == 'pattern':
                    pattern_type = violation.get('pattern_type', '')
                    if pattern_type in ['lm_hash_configured', 'cracked_computer_account']:
                        continue

                violation_type = type_mapping.get(violation['type'], 'Other')
                if violation_type in distribution['by_type']:
                    distribution['by_type'][violation_type] += 1

        return distribution
