from datetime import datetime
from .utils import find_cracked_accounts
from collections import defaultdict
from colorama import Fore, Style, init
from .node_type_cache import NodeTypeCache
from .account_escalation import AccountEscalationMixin
from .account_display import AccountDisplayMixin


class AccountAnalysis(AccountEscalationMixin, AccountDisplayMixin):

    def __init__(self, cracked_hashes, ntlmv2_hashes, ntds_data, neo4j_data, diagnostics=None):
        self.neo4j_data = neo4j_data
        self.cracked_hashes = cracked_hashes
        self.ntlmv2_hashes = ntlmv2_hashes
        self.ntds_hashes = ntds_data
        self._diagnostics = diagnostics

        if ntds_data:
            self.cracked_accounts = find_cracked_accounts(cracked_hashes, ntlmv2_hashes, ntds_data)
        else:
            self.cracked_accounts = {}

        self._enabled_cracked_cache = None
        self.output_format = 'safe'
        self.user_details_mapping = {}
        self._all_user_data_cache = None

        self.sid_to_entity = {}
        self.entity_to_sid = {}
        self.computer_sids = set()
        self.user_sids = set()
        self.sid_to_username = {}
        self.username_to_sid = {}

        self._escalation_results_cache = {}
        self._escalation_paths_cache = {}
        self._cached_domain_name = None

        self.type_cache = NodeTypeCache(neo4j_data.conn if neo4j_data else None)

        if self._diagnostics and ntds_data:
            ntds_user_hashes = ntds_data[0] if ntds_data else {}
            domain = neo4j_data.get_domain_name() if neo4j_data else "unknown"
            self._diagnostics.password_audit[domain] = {
                "ntds_loaded": ntds_data is not None,
                "total_hashes": len(ntds_user_hashes) if ntds_user_hashes else 0,
                "potfile_loaded": cracked_hashes is not None,
                "potfile_entries": len(cracked_hashes) if cracked_hashes else 0,
                "cracked_accounts": len(self.cracked_accounts),
            }

        init(autoreset=True)
        self.risk_colors = {
            'Critical': Fore.MAGENTA,
            'High': Fore.RED,
            'Medium': Fore.YELLOW,
            'Low': Fore.GREEN,
            'Info': Fore.CYAN,
        }
        self.reset_color = Style.RESET_ALL
        self.category_to_risk_level = {}

    def has_enabled_cracked_accounts(self):
        if self._enabled_cracked_cache is not None:
            return self._enabled_cracked_cache
        if not self.cracked_accounts:
            self._enabled_cracked_cache = False
            return False
        all_user_data = self.get_all_user_data()
        enabled_users = {(u.get('username') or '').lower() for u in all_user_data if u.get('username') and u.get('enabled')}
        self._enabled_cracked_cache = any(u in enabled_users for u in self.cracked_accounts)
        return self._enabled_cracked_cache

    def populate_user_details(self, user_dict):
        username = (user_dict.get('username') or '').lower()
        if not username:
            return

        sid = user_dict.get('sid')

        user_dict['is_computer'] = username.endswith('$')

        self.user_details_mapping[username] = user_dict

        if sid:
            self.user_details_mapping[f"sid:{sid}"] = user_dict

            self.sid_to_entity[sid] = user_dict
            self.entity_to_sid[username] = sid

            if user_dict['is_computer']:
                self.computer_sids.add(sid)
            else:
                self.user_sids.add(sid)

        groups = user_dict.get('groups', [])
        dn = user_dict.get('dn') or user_dict.get('distinguishedname', '') or ''
        user_dict['is_domain_controller'] = (
            any(g.lower() in ['domain controllers', 'enterprise domain controllers'] for g in groups) or
            (dn and 'OU=DOMAIN CONTROLLERS' in dn.upper())
        )

    def _get_entity_details(self, identifier):
        if not identifier:
            return None

        details = None
        is_sid = isinstance(identifier, str) and identifier.startswith('S-1-')
        is_name_prefixed = isinstance(identifier, str) and identifier.startswith('name:')

        if is_sid:
            if identifier in self.sid_to_entity:
                details = self.sid_to_entity[identifier]
            elif f"sid:{identifier}" in self.user_details_mapping:
                details = self.user_details_mapping[f"sid:{identifier}"]
            else:
                 for _, user_data in self.user_details_mapping.items():
                     if user_data.get('sid') == identifier:
                         details = user_data
                         break

        elif is_name_prefixed:
            username = identifier.split(':', 1)[1].lower()
            if username in self.user_details_mapping:
                details = self.user_details_mapping[username]
            elif f"{username}$" in self.user_details_mapping:
                 details = self.user_details_mapping[f"{username}$"]
            elif '.' in username:
                short_name = username.split('.')[0]
                if short_name in self.user_details_mapping:
                    details = self.user_details_mapping[short_name]
                elif f"{short_name}$" in self.user_details_mapping:
                    details = self.user_details_mapping[f"{short_name}$"]

        elif isinstance(identifier, str):
             username = identifier.lower()
             if username in self.user_details_mapping:
                 details = self.user_details_mapping[username]
             elif f"{username}$" in self.user_details_mapping:
                 details = self.user_details_mapping[f"{username}$"]

        if details:
            default_username = identifier.split(':', 1)[1] if is_name_prefixed else identifier if not is_sid else 'UnknownSID'
            details.setdefault('username', details.get('username', default_username))

            if is_sid and not details.get('sid'):
                details['sid'] = identifier
            details.setdefault('sid', None)

            derived_is_computer = (is_sid and identifier in self.computer_sids) or \
                                  ((details.get('username') or '').endswith('$'))
            details['is_computer'] = details.get('is_computer', derived_is_computer)

            details.setdefault('groups', [])
            details.setdefault('enabled', False)
            details.setdefault('constrainedDelegation', None)
            details.setdefault('passwordLastChanged', None)
        elif is_sid:
            details = {'sid': identifier, 'username': f'UnknownSID({identifier[-4:]})', 'is_computer': identifier in self.computer_sids, 'enabled': False, 'groups': []}
        else:
            return None

        return details

    def ensure_user_details_populated(self, force_refresh=False):
        if not self.user_details_mapping or force_refresh:
            all_user_data = self.get_all_user_data(force_refresh)

            if force_refresh:
                self.user_details_mapping.clear()
                self.sid_to_entity.clear()
                self.entity_to_sid.clear()
                self.computer_sids.clear()
                self.user_sids.clear()

            for user in all_user_data:
                if user and user.get('username'):
                    self.populate_user_details(user)

    def set_output_format(self, output_format):
        self.output_format = output_format

    def get_all_user_data(self, force_refresh=False):
        if self._all_user_data_cache is None or force_refresh:
            self._all_user_data_cache = self.neo4j_data.get_all_users_with_attributes(force_refresh=force_refresh)

        return self._all_user_data_cache

    def find_and_display_shared_accounts(self, output_format='safe'):
        if self.ntds_hashes is None:
            return "Account with Shared Password:\nTotal Accounts with Shared Passwords: 0\n\nNo accounts with shared passwords found.", {}
        ntds_user_hashes, _ = self.ntds_hashes

        detailed_line = []
        shared_accounts_summary = {}

        all_user_data = self.get_all_user_data()
        self.ensure_user_details_populated()

        enabled_accounts = {user.get('username', '').lower(): user
                            for user in all_user_data
                            if user.get('username') and user.get('enabled')}

        disabled_accounts = {user.get('username', '').lower(): user
                             for user in all_user_data
                             if user.get('username') and not user.get('enabled')}

        hash_counts = defaultdict(list)
        BLANK_HASH = '31D6CFE0D16AE931B73C59D7E0C089C0'

        for username, hash_value in ntds_user_hashes.items():
            username_lower = username.lower()
            user = enabled_accounts.get(username_lower) or disabled_accounts.get(username_lower)

            if user is not None:
                entry = {
                    'username': username,
                    'isAdmin': user.get('isAdmin', False),
                    'enabled': user.get('enabled', False),
                    'lastLogon': self.format_last_login(user.get('lastLogon', 'N/A'), user)
                }
                hash_counts[hash_value].append(entry)

        shared_enabled_groups = {}
        total_shared_accounts_count = 0

        for hash_value, accounts_list in hash_counts.items():
            enabled_users_in_group = [acc for acc in accounts_list if acc['enabled']]
            if len(enabled_users_in_group) > 1:
                shared_enabled_groups[hash_value] = enabled_users_in_group
                total_shared_accounts_count += len(enabled_users_in_group)

                shared_accounts_summary[hash_value] = [account['username'] for account in enabled_users_in_group]

        detailed_line.append("Account with Shared Password:")
        detailed_line.append(f"Total Accounts with Shared Passwords: {total_shared_accounts_count}\n")

        if not shared_enabled_groups:
             detailed_line.append("No accounts with shared passwords found.")
        else:
            sorted_hash_groups = sorted(shared_enabled_groups.items(), key=lambda item: len(item[1]), reverse=True)

            for hash_value, accounts in sorted_hash_groups:
                if hash_value.upper() == BLANK_HASH:
                    display_password = "(blank)"
                else:
                    display_password = self.cracked_hashes.get(hash_value, "Not cracked")

                if output_format == 'safe':
                    detailed_line.append(f"(Occurrences: {len(accounts)})")
                else:
                    password_text = display_password
                    hash_text = hash_value
                    detailed_line.append(f"{hash_text} (Occurrences: {len(accounts)}) - Password: {password_text}")

                sorted_accounts_in_group = sorted(accounts, key=lambda acc: acc['username'].lower())

                for account in sorted_accounts_in_group:
                    admin_tag = ' (admin)' if account['isAdmin'] else ''
                    detailed_line.append(f"    {account['username']}{admin_tag} - Last login: {account['lastLogon']}")

                detailed_line.append("")

        report_string = "\n".join(detailed_line).strip() + "\n"
        return report_string, shared_accounts_summary

    def format_last_login(self, timestamp, user):
        if timestamp in (-1.0, "0", "-1.0") or user is None:
            return "Never"
        try:
            if isinstance(user, dict):
                last_logon = user.get('lastLogon')
            else:
                last_logon = timestamp

            if not last_logon:
                return "Unknown"

            try:
                last_logon_int = int(float(last_logon))
            except (ValueError, TypeError):
                return "Unknown"

            date = datetime.fromtimestamp(last_logon_int)
            if date.year == 1970:
                return "Never"
            else:
                formatted_date = date.strftime('%m/%d/%Y')
                return formatted_date

        except (ValueError, TypeError, OSError, OverflowError):
            return "Unknown"

    def _has_weak_password(self, username):
        if self.ntds_hashes is None or self.cracked_hashes is None:
            return False

        ntds_user_hashes, _ = self.ntds_hashes
        normalised_username = username.strip().lower()

        user_hash = ntds_user_hashes.get(normalised_username)
        if not user_hash:
            return False

        is_blank = user_hash.upper() == "31D6CFE0D16AE931B73C59D7E0C089C0"
        is_cracked = user_hash in self.cracked_hashes

        return is_blank or is_cracked
