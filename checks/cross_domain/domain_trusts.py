from .base import CrossDomainCheck, CrossDomainRegistry


@CrossDomainRegistry.register
class DomainTrustCheck(CrossDomainCheck):
    RISK_LEVEL = "Info"
    CATEGORY_NAME = "Domain Trust Relationships"
    REQUIRES_NTDS = False

    def execute(self):
        query = """
        MATCH (d1:Domain)-[r]->(d2:Domain)
        RETURN d1.name as source, d2.name as target, type(r) as trust_type,
               r.trusttype as trust_category, r.transitive as transitive,
               r.sidfilteringenabled as sid_filtering,
               r.tgtdelegationenabled as tgt_delegation
        """
        try:
            results = self.deps.conn.query(query, name="domain_trusts")
        except Exception as e:
            if self.deps.diagnostics:
                self.deps.diagnostics.record_error("cross_domain:domain_trusts", e)
            return []

        findings = []
        for row in results:
            finding = {
                'source_domain': row.get('source'),
                'target_domain': row.get('target'),
                'trust_type': row.get('trust_type'),
                'trust_category': row.get('trust_category'),
                'transitive': row.get('transitive', False),
                'sid_filtering': row.get('sid_filtering', True),  # Default safe
                'tgt_delegation': row.get('tgt_delegation', False),
            }
            if not finding['sid_filtering']:
                finding['risk'] = 'SID filtering disabled — SID history spoofing possible'
            findings.append(finding)
        return findings

    @classmethod
    def to_display_results(cls, findings):
        results = {}
        for f in findings:
            key = f"{f['source_domain']} -> {f['target_domain']}"
            parts = []
            trust_info = f.get('trust_type', 'Unknown')
            if f.get('transitive'):
                trust_info += ", transitive"
            parts.append(f"({trust_info})")
            if not f.get('sid_filtering', True):
                parts.append("SID filtering DISABLED")
            if f.get('tgt_delegation'):
                parts.append("TGT delegation ENABLED")
            results[key] = " — ".join(parts)
        return results
