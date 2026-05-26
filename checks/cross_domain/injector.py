import inspect
from .base import CrossDomainRegistry


def _display_results(results, category_color, category, content, count, reset_color):
    content.append(f"\n  {category}: {count}")
    prev_multiline = False
    for index, (display_key, description) in enumerate(results.items()):
        is_multiline = bool(description) and description.lstrip().startswith(('├─', '└─'))
        if index > 0 and (prev_multiline or is_multiline):
            content.append("")
        if not description:
            content.append(f"    ▶ {display_key}")
        elif is_multiline:
            content.append(f"    ▶ {display_key}")
            for line in description.split('\n'):
                content.append(f"      {line}")
        else:
            content.append(f"    ▶ {display_key} — {description}")
        prev_multiline = is_multiline
    return content


def _display_grouped_paths(results, category_color, category, content, count, reset_color):
    content.append(f"\n  {category}: {count}")
    for index, (display_key, description) in enumerate(results.items()):
        if index > 0:
            content.append("")
        # display_key is "Users with Shared Path (N): user1, user2"
        # description is "Cross-Domain Path: MemberOf -> ..."
        content.append(f"    {display_key}")
        if description:
            content.append(f"        ▶ {description}")
    return content


class CrossDomainDisplayAdapter:

    def __init__(self, display_type='standard'):
        self.display_type = display_type

    def get_display_method(self):
        if self.display_type == 'grouped_paths':
            return _display_grouped_paths
        return _display_results


def inject_cross_domain_results(account_analysis, cross_domain_results, ntds_available):
    if not cross_domain_results:
        return

    current_domain = None
    if hasattr(account_analysis, 'neo4j_data'):
        current_domain = account_analysis.neo4j_data.get_domain_name()

    check_class_map = {
        cls.CATEGORY_NAME: cls
        for cls in CrossDomainRegistry.get_all_checks()
        if cls.CATEGORY_NAME
    }

    if not hasattr(account_analysis, '_framework_display_content'):
        account_analysis._framework_display_content = {}
    if not hasattr(account_analysis, '_framework_categories_for_stats'):
        account_analysis._framework_categories_for_stats = {}

    for category_name, data in cross_domain_results.items():
        risk_level = data['risk_level']
        findings = data['findings']

        check_class = check_class_map.get(category_name)
        if not check_class:
            continue

        if check_class.REQUIRES_NTDS and not ntds_available:
            continue

        sig = inspect.signature(check_class.to_display_results)
        if 'source_domain' in sig.parameters:
            results = check_class.to_display_results(findings, source_domain=current_domain)
            adapter = CrossDomainDisplayAdapter(display_type='grouped_paths')
        else:
            results = check_class.to_display_results(findings)
            adapter = CrossDomainDisplayAdapter(display_type='standard')

        if not results:
            continue

        total_count = results.pop('__total_user_count__', None)
        display_count = total_count if total_count is not None else len(results)

        if risk_level not in account_analysis._framework_display_content:
            account_analysis._framework_display_content[risk_level] = []
        account_analysis._framework_display_content[risk_level].append({
            'category': category_name,
            'count': display_count,
            'results': results,
            'check_instance': adapter,
            'password_audit': check_class.REQUIRES_NTDS,
        })

        if risk_level not in account_analysis._framework_categories_for_stats:
            account_analysis._framework_categories_for_stats[risk_level] = {}
        account_analysis._framework_categories_for_stats[risk_level][category_name] = {
            'count': display_count,
            'results': results,
            'entity_type': 'user',
        }
