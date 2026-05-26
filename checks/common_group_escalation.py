from checks.core import check, DisplayTypes
from checks.group_analysis_base import GroupAnalysisCheck


@check(risk="High", category="Common Groups with Privilege Escalation Paths",
       entity="group", data=[], display=DisplayTypes.GROUP_ANALYSIS)
class CommonGroupEscalationCheck(GroupAnalysisCheck):
    def execute(self):
        all_user_data = self.account_analysis.get_all_user_data()
        total_enabled_users = sum(1 for u in all_user_data
                                  if u.get('enabled') and not u.get('is_computer'))
        if total_enabled_users == 0:
            return {}

        threshold_count = max(1, int(0.35 * total_enabled_users))

        raw = self.neo4j_data.get_common_groups_analysis(
            threshold_count=threshold_count,
            total_user_count=total_enabled_users
        )
        if not raw:
            return {}

        processed = []
        for record in raw:
            entry = self._process_record(record)
            if entry:
                processed.append(entry)
        return self._build_results(processed)
