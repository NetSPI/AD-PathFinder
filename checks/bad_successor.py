from checks.core import Check, check


@check(risk="High", category="BadSuccessor - Default Groups with OU Privileges",
       entity="user", data=["bad_successor_ou_privileges"])
class BadSuccessorCheck(Check):
    
    CRITICAL_GROUPS_BY_SID = {
        'S-1-5-11': 'AUTHENTICATED USERS',
        '-513': 'DOMAIN USERS',
        '-515': 'DOMAIN COMPUTERS',
        'S-1-1-0': 'EVERYONE',
        'S-1-5-32-545': 'USERS',
    }

    DANGEROUS_PERMISSIONS = {
        'GenericAll', 'WriteOwner', 'WriteDacl', 'Owns',
        'GenericWrite', 'WriteOwnerRaw', 'OwnsRaw',
        'WriteGPLink', 'GPLink', 'CreateChild',
    }
    
    def execute(self):
        return self.check_critical_groups_ou_privileges()
    
    def check_critical_groups_ou_privileges(self):
        results = {}

        ou_privileges = self.get_bad_successor_ou_privileges()

        for record in ou_privileges:
            if not record:
                continue

            entity_sid = record.get('entity_sid', '')
            rel_type = record.get('relationship_type', '')
            target_name = record.get('target_name', record.get('ou_name', ''))

            for sid_pattern, group_display in self.CRITICAL_GROUPS_BY_SID.items():
                if entity_sid and self._matches_sid_pattern(entity_sid, sid_pattern):
                    if rel_type in self.DANGEROUS_PERMISSIONS:
                        description = f"{group_display} HAS {rel_type.upper()} ON OU: {target_name}"
                        results[description] = self.finding("", inline=True)
                    break  # Only match one group per entity

        return results
    
    def _matches_sid_pattern(self, entity_sid, pattern):
        if not entity_sid or not pattern:
            return False
        
        if pattern.startswith('S-1-'):
            return entity_sid.endswith(pattern)
        elif pattern.startswith('-'):
            if not entity_sid.endswith(pattern):
                return False
            prefix_pos = len(entity_sid) - len(pattern)
            if prefix_pos <= 0:
                return False
            preceding_char = entity_sid[prefix_pos - 1]
            return preceding_char.isdigit() or preceding_char == '-'
        else:
            return pattern in entity_sid