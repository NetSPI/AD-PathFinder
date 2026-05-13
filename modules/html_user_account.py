import html
from datetime import datetime

from .utils import analyse_usernames


class UserAccountAnalysisMixin:
    def generate_user_account_analysis_content(self):
        content = []
        content.append('        <h2>User Account Analysis</h2>')

        content.extend(self.generate_statistically_likely_usernames_content())
        content.extend(self.generate_kerberoastable_accounts_content())
        content.extend(self.generate_asrep_roastable_accounts_content())
        content.extend(self.generate_ntlmv2_hashes_content())
        content.extend(self.generate_krbtgt_password_age_content())

        return content

    def generate_statistically_likely_usernames_content(self):
        if not self.likely_usernames:
            return []

        cracked_usernames = [username.lower() for username, details in self.user_details.items() if details.get('enabled', False)]
        matched_usernames = analyse_usernames(cracked_usernames, self.likely_usernames)

        vulnerable_usernames = [username for username in matched_usernames
                                if self._has_weak_password(username) and self.user_details.get(username, {}).get('enabled', False)]

        if not vulnerable_usernames:
            return []

        content = []
        content.append('        <div class="section" id="likely_usernames-section">')
        content.append('            <h3>Statistically Likely Usernames</h3>')
        content.append('        <p><strong>Security Risk:</strong> The presence of statistically likely usernames in your organization, especially those with weak passwords, poses a significant security risk. Attackers often use databases of common usernames to enumerate valid accounts through Kerberos pre-authentication. Once valid usernames are identified, they can be targeted with password spraying attacks, potentially leading to unauthorized access.</p>')

        content.append('            <p>The following enabled usernames were found in the statistically likely usernames list and have a weak password:</p>')
        content.append('            <ul>')
        for username in vulnerable_usernames:
            content.append(f'                <li>{self.make_username_hoverable(username)}</li>')
        content.append('            </ul>')

        content.append('        </div>')
        return content

    def generate_kerberoastable_accounts_content(self):
        kerberoastable_accounts = [username for username, details in self.user_details.items()
                                   if details.get('kerberoastable', False) and self._has_weak_password(username) and details.get('enabled', False)]

        if not kerberoastable_accounts:
            return []

        content = []
        content.append('        <div class="section" id="kerberoastable_accounts-section">')
        content.append('            <h3>Kerberoastable Accounts</h3>')
        content.append('        <p><strong>Security Risk:</strong> Kerberoastable accounts are those with Service Principal Names (SPNs) set. These accounts are vulnerable to offline password cracking attacks, which could lead to privilege escalation if the account has significant permissions.</p>')

        content.append('            <p>The following enabled accounts are Kerberoastable and have a weak password:</p>')
        content.append('            <ul>')
        for username in kerberoastable_accounts:
            content.append(f'                <li>{self.make_username_hoverable(username)}</li>')
        content.append('            </ul>')

        content.append('        </div>')
        return content

    def generate_asrep_roastable_accounts_content(self):
        asrep_roastable_accounts = [username for username, details in self.user_details.items()
                                    if details.get('asrepRoastable', False) and self._has_weak_password(username) and details.get('enabled', False)]

        if not asrep_roastable_accounts:
            return []

        content = []
        content.append('        <div class="section" id="asrep_roastable_accounts-section">')
        content.append('            <h3>AS-REP Roastable Accounts</h3>')
        content.append('        <p><strong>Security Risk:</strong> AS-REP Roastable accounts have the "Do not require Kerberos preauthentication" option enabled. This configuration allows attackers to request authentication data for these accounts without prior authentication, making them vulnerable to offline password cracking attacks.</p>')

        content.append('            <p>The following enabled accounts are AS-REP Roastable and have a weak password:</p>')
        content.append('            <ul>')
        for username in asrep_roastable_accounts:
            content.append(f'                <li>{self.make_username_hoverable(username)}</li>')
        content.append('            </ul>')

        content.append('        </div>')
        return content

    def generate_krbtgt_password_age_content(self):
        content = []
        content.append('        <div class="section">')
        content.append('            <h3>KRBTGT Account Password Age</h3>')
        content.append('        <p><strong>Security Risk:</strong> The KRBTGT account is used to encrypt Kerberos tickets. If its password is not changed regularly, it can be used to create golden tickets, potentially allowing persistent, undetected access to the domain.</p>')

        password_last_changed = None
        if self.neo4j_data:
            password_last_changed = self.neo4j_data.get_krbtgt_password_last_changed()

        if password_last_changed and password_last_changed not in ['Never', 'Unknown', 0, -1]:
            try:
                pwd_date = datetime.fromtimestamp(int(password_last_changed))
                age_days = (datetime.now() - pwd_date).days
                formatted_date = pwd_date.strftime("%m/%d/%Y")

                if age_days > 180:
                    content.append(f'        <p><strong>Warning:</strong> The {self.make_username_hoverable("krbtgt")} account password is over 6 months old. It was last changed on {formatted_date}.</p>')
                else:
                    content.append(f'        <p>The {self.make_username_hoverable("krbtgt")} account password was last changed on {formatted_date}. This is within the recommended 6-month timeframe.</p>')
            except (ValueError, TypeError, OverflowError):
                content.append(f'        <p>Error processing the last password change date for the {self.make_username_hoverable("krbtgt")} account. Raw value: {password_last_changed}</p>')
        else:
            content.append('        <p>KRBTGT account information not found.</p>')

        content.append('        </div>')
        return content

    def generate_ntlmv2_hashes_content(self):
        matched_accounts = []
        for username, password in self.ntlmv2_hashes.items():
            if username in self.user_details and self._has_weak_password(username):
                matched_accounts.append((username, password))

        if not matched_accounts:
            return []

        content = []
        content.append('        <div class="section">')
        content.append('            <h3>Cracked NTLMv2 Hashes</h3>')
        content.append('        <p><strong>Security Risk:</strong> These accounts have had their NTLMv2 hashes cracked, potentially through tools like Responder or MITM6. This indicates that these accounts may have responded to network-based attacks, exposing their credentials.</p>')

        content.append('            <p>The following accounts have cracked NTLMv2 hashes and exist in the domain with weak passwords:</p>')
        content.append('            <ul>')
        for username, password in matched_accounts:
            content.append(f'                <li>{self.make_username_hoverable(username)}</li>')
        content.append('            </ul>')

        content.append('        </div>')
        return content
