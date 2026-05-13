from collections import defaultdict
from .base import CrossDomainCheck, CrossDomainRegistry, BLANK_HASH


@CrossDomainRegistry.register
class CrackedPasswordReuseCheck(CrossDomainCheck):
    RISK_LEVEL = "High"
    CATEGORY_NAME = "Cracked Password Reused by Different User Across Domains"
    REQUIRES_NTDS = True

    def execute(self):
        hash_domain_users = defaultdict(lambda: defaultdict(set))

        for domain, (ntds_user_hashes, _) in self.deps.domain_hashes.items():
            for username, nt_hash in ntds_user_hashes.items():
                nt_hash = nt_hash.lower()
                if nt_hash == BLANK_HASH:
                    continue
                if nt_hash not in self.deps.cracked_hashes:
                    continue
                hash_domain_users[nt_hash][domain].add(username)

        user_matches = defaultdict(list)

        for nt_hash, domain_users in hash_domain_users.items():
            if len(domain_users) < 2:
                continue

            domains = list(domain_users.keys())
            for i, src_domain in enumerate(domains):
                for src_user in domain_users[src_domain]:
                    for j, tgt_domain in enumerate(domains):
                        if i == j:
                            continue
                        for tgt_user in domain_users[tgt_domain]:
                            if src_user.lower() == tgt_user.lower():
                                continue
                            user_matches[(src_user, src_domain)].append(
                                (tgt_user, tgt_domain))

        findings = []
        for (username, domain), matches in sorted(user_matches.items(), key=lambda x: x[0][0].lower()):
            by_domain = defaultdict(list)
            for other_user, other_domain in matches:
                by_domain[other_domain].append(other_user)

            match_domains = []
            for other_domain in sorted(by_domain):
                match_domains.append({
                    'domain': other_domain,
                    'users': sorted(by_domain[other_domain], key=str.lower),
                })

            findings.append({
                'username': username,
                'domain': domain,
                'match_domains': match_domains,
            })

        return findings

    @classmethod
    def to_display_results(cls, findings):
        results = {}
        for f in findings:
            key = f"{f['username'].upper()} ({f['domain']})"
            matched = []
            for match in f['match_domains']:
                for user in match['users']:
                    matched.append(f"{user.upper()} ({match['domain']})")
            lines = []
            for i, entry in enumerate(matched):
                connector = "└─" if i == len(matched) - 1 else "├─"
                lines.append(f"{connector} {entry}")
            results[key] = "\n".join(lines)
        return results
