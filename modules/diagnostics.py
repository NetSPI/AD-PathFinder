import json
import time
from datetime import datetime


def compute_audit_mode(ad, pwd):
    if ad and pwd:
        return "ad_pwd_audit"
    if ad:
        return "ad_audit"
    if pwd:
        return "pwd_audit"
    return "interactive"


class DiagnosticsCollector:

    def __init__(self):
        self.start_time = time.time()
        self.queries = []
        self.checks = []
        self.skipped = []
        self.check_order = {}
        self.entity_summary = {}
        self.escalation_paths = {}
        self.escalation_batches = {}
        self.password_audit = {}
        self.cross_domain_checks = {}
        self.mssql_sccm = {}
        self.report_generation = {}
        self.errors = []
        self.args = {}
        self.domains = []

    def record_query(self, name, duration_ms, result_count, cached=False,
                     batch_count=None, cache_hits=None, cache_misses=None,
                     success=True):
        entry = {
            "name": name,
            "duration_ms": round(duration_ms, 1),
            "result_count": result_count,
            "cached": cached
        }
        if batch_count is not None:
            entry["batch_count"] = batch_count
        if cache_hits is not None:
            entry["cache_hits"] = cache_hits
        if cache_misses is not None:
            entry["cache_misses"] = cache_misses
        if not success:
            entry["success"] = False
        self.queries.append(entry)

    def record_check(self, name, risk_level, category, entity_type,
                     duration_ms, entities_input, entities_after_filter,
                     filtered_breakdown, findings_count, finding_sids=None,
                     unique_paths=None, domain=None):
        entry = {
            "name": name,
            "risk_level": risk_level,
            "category": category,
            "entity_type": entity_type,
            "duration_ms": round(duration_ms, 1),
            "entities_input": entities_input,
            "entities_after_filter": entities_after_filter,
            "filtered_breakdown": filtered_breakdown,
            "findings_count": findings_count
        }
        if finding_sids is not None:
            entry["finding_sids"] = finding_sids
        if unique_paths is not None:
            entry["unique_paths"] = unique_paths
        if domain is not None:
            entry["domain"] = domain
        self.checks.append(entry)

    def record_error(self, source, error, domain=None):
        entry = {
            "source": source,
            "error": str(error),
            "timestamp": datetime.now().isoformat()
        }
        if domain is not None:
            entry["domain"] = domain
        self.errors.append(entry)

    def record_escalation_batch(self, domain, batch_num, size, duration_ms,
                                 paths_found, success=True, error=None):
        if domain not in self.escalation_batches:
            return
        entry = {
            "batch_num": batch_num,
            "size": size,
            "duration_ms": round(duration_ms, 1),
            "paths_found": paths_found,
        }
        if not success:
            entry["success"] = False
            if error is not None:
                entry["error"] = str(error)
        self.escalation_batches[domain]["batches"].append(entry)

    def record_skipped(self, check_name, reason, domain=None):
        entry = {
            "name": check_name,
            "reason": reason,
        }
        if domain is not None:
            entry["domain"] = domain
        self.skipped.append(entry)

    def to_dict(self):
        duration = time.time() - self.start_time
        query_durations = [q["duration_ms"] for q in self.queries]
        slowest = max(self.queries, key=lambda q: q["duration_ms"]) if self.queries else None

        checks_with_findings = [c for c in self.checks if c["findings_count"] > 0]
        checks_errored = len([e for e in self.errors if e["source"].startswith("check:")])
        skipped_breakdown = {}
        for s in self.skipped:
            reason_key = s["reason"].split(":", 1)[0]
            skipped_breakdown[reason_key] = skipped_breakdown.get(reason_key, 0) + 1

        by_risk = {}
        for c in self.checks:
            rl = c["risk_level"]
            if rl not in by_risk:
                by_risk[rl] = {"checks_run": 0, "checks_with_findings": 0, "total_findings": 0}
            by_risk[rl]["checks_run"] += 1
            if c["findings_count"] > 0:
                by_risk[rl]["checks_with_findings"] += 1
            by_risk[rl]["total_findings"] += c["findings_count"]

        return {
            "run_metadata": {
                "timestamp": datetime.now().isoformat(),
                "duration_seconds": round(duration, 1),
                "domains": self.domains,
                "mode": self.args.get("mode", "unknown"),
                "args": self.args
            },
            "neo4j_queries": {
                "summary": {
                    "total_queries": len(self.queries),
                    "total_duration_ms": round(sum(query_durations), 1) if query_durations else 0,
                    "slowest_query": {
                        "name": slowest["name"],
                        "duration_ms": slowest["duration_ms"]
                    } if slowest else None
                },
                "queries": self.queries
            },
            "entity_summary": self.entity_summary,
            "checks": {
                "summary": {
                    "total_registered": len(self.checks) + len(self.skipped) + checks_errored,
                    "total_executed": len(self.checks),
                    "total_skipped": len(self.skipped),
                    "total_with_findings": len(checks_with_findings),
                    "total_with_zero_findings": len(self.checks) - len(checks_with_findings),
                    "total_errored": checks_errored,
                    "total_findings": sum(c["findings_count"] for c in self.checks),
                    "skipped_breakdown": skipped_breakdown,
                },
                "by_risk_level": by_risk,
                "detail": self.checks,
                "skipped": self.skipped,
            },
            "escalation_paths": self.escalation_paths,
            "escalation_batches": self.escalation_batches,
            "password_audit": self.password_audit,
            "cross_domain_checks": self.cross_domain_checks,
            "mssql_sccm": self.mssql_sccm,
            "check_ordering": self.check_order,
            "report_generation": self.report_generation,
            "errors": self.errors
        }

    def write(self, output_path):
        with open(output_path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
