import html


class CrossDomainMixin:
    def _generate_cross_domain_tab_content(self):
        lines = []
        lines.append('        <h2>Cross-Domain Analysis</h2>')

        if not self.cross_domain_data:
            lines.append('        <p>No cross-domain findings detected.</p>')
            return lines

        if 'Admin Account with Weak Password in Another Domain' in self.cross_domain_data:
            data = self.cross_domain_data['Admin Account with Weak Password in Another Domain']
            findings = data['findings']
            user_entries = {}
            for f in findings:
                uname = f.get('username', '')
                if uname not in user_entries:
                    user_entries[uname] = []
                user_entries[uname].append(f)

            lines.append('    <div class="section" id="cross-domain-admin-weak-section">')
            lines.append(f'        <h3>Admin Accounts with Weak Password in Another Domain: {len(user_entries)}</h3>')
            lines.append('        <p><strong>Security Risk:</strong> These accounts have administrative privileges in one domain but their password has been cracked in the NTDS dump of another domain. An attacker who compromises the weaker domain can reuse these credentials to escalate into the domain where the account holds admin rights.</p>')
            lines.append('        <p>The following admin accounts have a cracked password in another domain:</p>')
            lines.append('        <ul>')
            for uname, entries in user_entries.items():
                tooltip = self._build_cross_domain_tooltip(uname, entries, 'admin_weak')
                span = self._create_hoverable_tooltip_span((uname or '').lower(), tooltip)
                lines.append(f'                <li>{span}</li>')
            lines.append('        </ul>')
            lines.append('    </div>')

        if 'Account with Shared Password Another Domain' in self.cross_domain_data:
            data = self.cross_domain_data['Account with Shared Password Another Domain']
            findings = data['findings']
            lines.append('    <div class="section" id="cross-domain-same-user-section">')
            lines.append(f'        <h3>Account with Shared Password Another Domain: {len(findings)}</h3>')
            lines.append('        <p><strong>Security Risk:</strong> The same username exists in multiple domains and has an identical NT hash in each, confirming the user set the same password everywhere. Cracking the password in any one domain compromises the account in all domains.</p>')
            lines.append('        <p>The following usernames have the same password in every domain where they appear:</p>')
            lines.append('        <ul>')
            for f in findings:
                uname = f.get('username') or ''
                tooltip = self._build_cross_domain_tooltip(uname, [f], 'same_user')
                span = self._create_hoverable_tooltip_span(uname.lower(), tooltip)
                lines.append(f'                <li>{span}</li>')
            lines.append('        </ul>')
            lines.append('    </div>')

        if 'Cracked Password Reused by Different User Across Domains' in self.cross_domain_data:
            data = self.cross_domain_data['Cracked Password Reused by Different User Across Domains']
            findings = data['findings']
            lines.append('    <div class="section" id="cross-domain-password-reuse-section">')
            lines.append(f'        <h3>Cracked Password Reused by Different User Across Domains: {len(findings)}</h3>')
            lines.append('        <p><strong>Security Risk:</strong> A cracked password in one domain is shared by a different user in another domain. An attacker can spray this known password across domains to compromise additional accounts without further cracking.</p>')
            lines.append('        <p>The following users share a cracked password with users in other domains:</p>')
            lines.append('        <ul>')
            for f in findings:
                username = f.get('username') or ''
                domain = f.get('domain') or ''
                tooltip = self._build_cross_domain_tooltip(username, [f], 'password_reuse')
                label = f'{html.escape(username.lower())} ({html.escape(domain.lower())})'
                span = self._create_hoverable_tooltip_span(label, tooltip)
                lines.append(f'                <li>{span}</li>')
            lines.append('        </ul>')
            lines.append('    </div>')

        if 'Domain Trust Relationships' in self.cross_domain_data:
            data = self.cross_domain_data['Domain Trust Relationships']
            findings = data['findings']
            lines.append('    <div class="section" id="cross-domain-trusts-section">')
            lines.append(f'        <h3>Domain Trust Relationships: {len(findings)}</h3>')
            lines.append('        <p><strong>Security Risk:</strong> Domain trusts define how authentication and authorisation flow between domains. Misconfigured trusts, especially those with SID filtering disabled, can allow attackers to perform SID history injection attacks and escalate privileges across domain boundaries.</p>')
            lines.append('        <p>The following trust relationships were identified:</p>')
            lines.append('        <ul>')
            for f in findings:
                tooltip = self._build_cross_domain_tooltip(None, [f], 'trust')
                label = f'{(f.get("source_domain") or "").lower()} -> {(f.get("target_domain") or "").lower()}'
                span = self._create_hoverable_tooltip_span(label, tooltip)
                lines.append(f'                <li>{span}</li>')
            lines.append('        </ul>')
            lines.append('    </div>')

        return lines

    def _build_cross_domain_tooltip(self, username, entries, check_type):
        parts = []

        if check_type == 'admin_weak':
            user_data = self.user_details.get(username.lower() if username else '', {})
            if user_data:
                parts.append(f'<strong>Username:</strong> {html.escape((user_data.get("username") or username or "").lower())}')
                parts.append(f'<strong>Domain:</strong> {html.escape((user_data.get("domain") or "").lower())}')
                if user_data.get('description'):
                    parts.append(f'<strong>Description:</strong> {html.escape(str(user_data.get("description", "")))}')
                parts.append(f'<strong>Enabled:</strong> {"Yes" if user_data.get("enabled") else "No"}')
                parts.append(f'<strong>Admin:</strong> {"Yes" if user_data.get("isAdmin") else "No"}')
            else:
                parts.append(f'<strong>Username:</strong> {html.escape((username or "").lower())}')

            parts.append('<br><strong>Cross-Domain Findings:</strong>')
            for e in entries:
                parts.append(f'&bull; Admin in <strong>{html.escape((e.get("admin_domain") or "").lower())}</strong>, '
                             f'cracked password in <strong>{html.escape((e.get("weak_password_domain") or "").lower())}</strong>')

        elif check_type == 'same_user':
            user_data = self.user_details.get(username.lower() if username else '', {})
            if user_data:
                parts.append(f'<strong>Username:</strong> {html.escape((user_data.get("username") or username or "").lower())}')
                parts.append(f'<strong>Domain:</strong> {html.escape((user_data.get("domain") or "").lower())}')
                parts.append(f'<strong>Enabled:</strong> {"Yes" if user_data.get("enabled") else "No"}')
                parts.append(f'<strong>Admin:</strong> {"Yes" if user_data.get("isAdmin") else "No"}')
            else:
                parts.append(f'<strong>Username:</strong> {html.escape((username or "").lower())}')

            e = entries[0]
            parts.append(f'<strong>Password Cracked:</strong> {"Yes" if e.get("password_cracked") else "No"}')
            parts.append('<br><strong>Same Password In:</strong>')
            for domain in e.get('domains') or []:
                parts.append(f'&bull; {html.escape((domain or "").lower())}')

        elif check_type == 'password_reuse':
            user_data = self.user_details.get(username.lower() if username else '', {})
            if user_data:
                parts.append(f'<strong>Username:</strong> {html.escape((user_data.get("username") or username or "").lower())}')
                parts.append(f'<strong>Domain:</strong> {html.escape((user_data.get("domain") or "").lower())}')
                parts.append(f'<strong>Enabled:</strong> {"Yes" if user_data.get("enabled") else "No"}')
                parts.append(f'<strong>Admin:</strong> {"Yes" if user_data.get("isAdmin") else "No"}')
            else:
                parts.append(f'<strong>Username:</strong> {html.escape((username or "").lower())}')

            e = entries[0]
            parts.append(f'<strong>Source Domain:</strong> {html.escape(str(e.get("domain", "")).lower())}')
            parts.append('<br><strong>Shares cracked password with:</strong>')
            for match in e.get('match_domains') or []:
                domain = html.escape((match.get('domain') or '').lower())
                for user in match.get('users') or []:
                    parts.append(f'&bull; {html.escape((user or "").lower())} ({domain})')

        elif check_type == 'trust':
            e = entries[0]
            parts.append(f'<strong>Source:</strong> {html.escape(str(e.get("source_domain", "")).lower())}')
            parts.append(f'<strong>Target:</strong> {html.escape(str(e.get("target_domain", "")).lower())}')
            parts.append(f'<strong>Trust Type:</strong> {html.escape(str(e.get("trust_type", "Unknown")))}')
            parts.append(f'<strong>Transitive:</strong> {"Yes" if e.get("transitive") else "No"}')
            sid_filtering = e.get('sid_filtering', True)
            sid_text = 'Enabled' if sid_filtering else '<strong style="color:red">DISABLED</strong>'
            parts.append(f'<strong>SID Filtering:</strong> {sid_text}')
            parts.append(f'<strong>TGT Delegation:</strong> {"Yes" if e.get("tgt_delegation") else "No"}')

        return '<br>'.join(parts)
