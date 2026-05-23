from checks.core import Check, check


@check(risk="High", category="BadSuccessor - Privileged OU/Container Control",
       entity="user", data=["bad_successor_ou_privileges"])
class BadSuccessorCheck(Check):

    def execute(self):
        results = {}
        for record in self.get_bad_successor_ou_privileges():
            if not record:
                continue
            entity_name = record.get('entity_name') or record.get('entity_id') or 'Unknown'
            rel_type = record.get('relationship_type') or ''
            target_type = record.get('target_type', 'OU')
            target_name = record.get('target_name') or record.get('target_id') or 'Unknown'
            description = f"{entity_name} HAS {rel_type.upper()} ON {target_type.upper()}: {target_name}"
            results[description] = self.finding("", inline=True)
        return results
