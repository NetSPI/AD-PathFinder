from concurrent.futures import ThreadPoolExecutor, as_completed
from checks.cross_domain.base import CrossDomainRegistry


class CrossDomainManager:
    def __init__(self, dependencies, diagnostics=None):
        self.dependencies = dependencies
        self._diagnostics = diagnostics

    def run_all_checks(self):
        checks = CrossDomainRegistry.get_all_checks()
        if not checks:
            return {}

        results = {}

        with ThreadPoolExecutor(max_workers=len(checks)) as executor:
            future_to_check = {
                executor.submit(self._run_single_check, check_class): check_class
                for check_class in checks
            }

            for future in as_completed(future_to_check):
                check_class = future_to_check[future]
                try:
                    result = future.result()
                    if result:
                        results[result['category']] = {
                            'risk_level': result['risk_level'],
                            'findings': result['findings'],
                            'count': result['count'],
                        }
                except Exception as e:
                    print(f"Warning: Cross-domain check {check_class.__name__} failed: {e}")
                    if self._diagnostics:
                        self._diagnostics.record_error(
                            f"cross_domain:{check_class.__name__}", e)

        if self._diagnostics and not self._diagnostics.cross_domain_checks:
            detail = []
            for category, data in results.items():
                detail.append({
                    "name": category,
                    "findings_count": data['count'],
                    "risk_level": data['risk_level']
                })
            self._diagnostics.cross_domain_checks = {
                "checks_run": len(checks),
                "checks_with_findings": len(results),
                "total_findings": sum(d['count'] for d in results.values()),
                "detail": detail
            }

        return results

    def _run_single_check(self, check_class):
        try:
            check = check_class(self.dependencies)
            findings = check.run()
            if findings:
                return {
                    'category': check.CATEGORY_NAME,
                    'risk_level': check.RISK_LEVEL,
                    'findings': findings,
                    'count': len(findings),
                }
        except Exception as e:
            print(f"Warning: Cross-domain check {check_class.__name__} failed: {e}")
            if self._diagnostics:
                self._diagnostics.record_error(
                    f"cross_domain:{check_class.__name__}", e)
        return None
