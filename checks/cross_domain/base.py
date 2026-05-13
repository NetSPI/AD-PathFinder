BLANK_HASH = '31d6cfe0d16ae931b73c59d7e0c089c0'


class CrossDomainDependencies:
    def __init__(self, conn, all_domains, domain_hashes=None,
                 cracked_hashes=None, per_domain_admin_users=None,
                 relationship_pattern=None, diagnostics=None):
        self.conn = conn
        self.all_domains = all_domains
        self.domain_hashes = domain_hashes or {}
        self.cracked_hashes = cracked_hashes or {}
        self.per_domain_admin_users = per_domain_admin_users or {}
        # Pipe-separated relationship pattern from neo4j_data.get_all_relationships()
        # e.g. "MemberOf|AdminTo|GenericAll|..."
        self.relationship_pattern = relationship_pattern or ""
        self.diagnostics = diagnostics

    def get_adaptive_workers(self, entity_count):
        if entity_count > 10000:
            return 8
        elif entity_count > 5000:
            return 6
        elif entity_count > 2000:
            return 4
        elif entity_count > 500:
            return 2
        return 1


class CrossDomainRegistry:
    checks = []

    @classmethod
    def register(cls, check_class):
        cls.checks.append(check_class)
        return check_class

    @classmethod
    def get_all_checks(cls):
        return cls.checks


class CrossDomainCheck:
    RISK_LEVEL = "High"
    CATEGORY_NAME = None
    REQUIRES_NTDS = False

    def __init__(self, dependencies):
        self.deps = dependencies

    def execute(self):
        raise NotImplementedError

    def run(self):
        if self.REQUIRES_NTDS and not self.deps.domain_hashes:
            return []
        return self.execute()

    @classmethod
    def to_display_results(cls, findings):
        return {str(i): str(f) for i, f in enumerate(findings)}
