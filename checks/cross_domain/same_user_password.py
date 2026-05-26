from collections import defaultdict
from .base import CrossDomainCheck, CrossDomainRegistry, BLANK_HASH


@CrossDomainRegistry.register
class SameUserPasswordCheck(CrossDomainCheck):
    RISK_LEVEL = "High"
    CATEGORY_NAME = "Account with Shared Password Another Domain"
    REQUIRES_NTDS = True

    def execute(self):
        user_domain_hashes = defaultdict(dict)

        for domain, (ntds_user_hashes, _) in self.deps.domain_hashes.items():
            for username, nt_hash in ntds_user_hashes.items():
                if nt_hash.lower() == BLANK_HASH:
                    continue
                user_domain_hashes[username][domain] = nt_hash.lower()

        findings = []
        for username, domain_hashes_map in user_domain_hashes.items():
            if len(domain_hashes_map) < 2:
                continue
            hashes = list(domain_hashes_map.values())
            if len(set(hashes)) == 1:
                findings.append({
                    'username': username,
                    'domains': list(domain_hashes_map.keys()),
                    'password_cracked': hashes[0] in self.deps.cracked_hashes,
                })

        findings.sort(key=lambda f: f['username'])
        return findings

    @classmethod
    def to_display_results(cls, findings):
        results = {}
        for f in findings:
            key = f['username'].upper()
            domains = f['domains']
            lines = []
            for i, domain in enumerate(domains):
                connector = "└─" if i == len(domains) - 1 else "├─"
                lines.append(f"{connector} {domain}")
            results[key] = "\n".join(lines)
        return results
