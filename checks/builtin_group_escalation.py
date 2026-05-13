from checks.core import check, DisplayTypes
from checks.group_analysis_base import GroupAnalysisCheck


@check(risk="Critical", category="Default Groups with Privilege Escalation Paths",
       entity="group", data=[], display=DisplayTypes.GROUP_ANALYSIS)
class BuiltinGroupEscalationCheck(GroupAnalysisCheck):
    def execute(self):
        raw = self.neo4j_data.get_builtin_groups_analysis()
        if not raw:
            return {}
        processed = []
        for record in raw:
            target_types = record.get('Target Object Types') or []
            if any('MSSQL' in str(l) for l in target_types) and not record.get('Target SQL Server'):
                continue
            entry = self._process_record(record)
            if entry:
                processed.append(entry)
        return self._build_results(processed)
