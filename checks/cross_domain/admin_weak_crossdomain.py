from .base import CrossDomainCheck, CrossDomainRegistry


@CrossDomainRegistry.register
class AdminWeakCrossDomainCheck(CrossDomainCheck):
    RISK_LEVEL = "Critical"
    CATEGORY_NAME = "Admin Account with Weak Password in Another Domain"
    REQUIRES_NTDS = True

    def execute(self):
        findings = []
        for admin_domain, admins in self.deps.per_domain_admin_users.items():
            for other_domain, (ntds_hashes, _) in self.deps.domain_hashes.items():
                if other_domain == admin_domain:
                    continue
                for admin_user in admins:
                    nt_hash = ntds_hashes.get(admin_user.lower())
                    if nt_hash and nt_hash in self.deps.cracked_hashes:
                        findings.append({
                            'username': admin_user,
                            'admin_domain': admin_domain,
                            'weak_password_domain': other_domain,
                        })

        findings.sort(key=lambda f: (f['admin_domain'], f['username']))
        return findings

    @classmethod
    def to_display_results(cls, findings):
        results = {}
        for f in findings:
            key = f['username'].upper()
            desc = f"admin in {f['admin_domain']}, cracked password in {f['weak_password_domain']}"
            if key in results:
                results[key] += f" | {desc}"
            else:
                results[key] = desc
        return results
