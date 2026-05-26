from .hv_groups import ADMIN_GROUP_NAMES
from .node_type_cache import (
    AD_REPORT_OBJECT_TYPES,
    ad_reportable_labels_from_labels,
    extract_ad_report_type_from_labels,
)


class GroupAnalysisMixin:
    def _normalise_group_target_labels(self, records):
        for record in records:
            raw_labels = list(record.get('Target Object Types') or [])
            record['Target Raw Object Types'] = raw_labels

            target_type = extract_ad_report_type_from_labels(raw_labels)
            current_type = record.get('Target Object Type')
            if target_type == 'Unknown' and current_type in AD_REPORT_OBJECT_TYPES:
                target_type = current_type

            reportable_labels = ad_reportable_labels_from_labels(raw_labels)
            if not reportable_labels and target_type != 'Unknown':
                reportable_labels = [target_type]

            record['Target Object Type'] = target_type
            record['Target Object Types'] = reportable_labels

        return records

    def get_builtin_groups_analysis(self, force_refresh=False):
        if not force_refresh and self.builtin_groups_paths_cache is not None:
            return self.builtin_groups_paths_cache

        # MSSQL relationships excluded — handled by dedicated MSSQL checks
        interesting_rels = ["Owns", "GenericAll", "GenericWrite", "WriteOwner", "WriteDacl",
                           "AdminTo", "CanPSRemote", "CanRDP", "ForceChangePassword",
                           "AllExtendedRights", "AddMember", "AddSelf", "AllowedToDelegate", "AllowedToAct",
                           "AddAllowedToAct",
                           "DCSync", "ReadLAPSPassword", "ReadGMSAPassword", "SyncLAPSPassword",
                           "DumpSMSAPassword", "SQLAdmin",
                           "WriteSPN", "AddKeyCredentialLink", "WriteAccountRestrictions",
                           "GPLink", "WriteGPLink", "GoldenCert", "ManageCA", "ManageCertificates",
                           "CoerceToTGT", "CoerceAndRelayNTLMToADCS",
                           "CoerceAndRelayNTLMToSMB", "CoerceAndRelayNTLMToLDAP", "CoerceAndRelayNTLMToLDAPS",
                           "CoerceAndRelayToSMB", "CoerceAndRelayToAdminService",
                           "AbuseTGTDelegation", "CrossForestTrust"]

        filtered_rels = [rel for rel in interesting_rels if rel.upper() not in self.excluded_relationships]

        domain_filter_clause = self._domain_condition("m")

        query = """
        MATCH (m:Group)
        WHERE (m.name STARTS WITH "DOMAIN USERS"
        OR m.name STARTS WITH "DOMAIN COMPUTERS"
        OR m.name STARTS WITH "AUTHENTICATED USERS"
        OR m.name STARTS WITH "EVERYONE"
        OR m.name STARTS WITH "USERS"
        OR m.objectid ENDS WITH "-513"   // Domain Users fallback
        OR m.objectid ENDS WITH "-515"   // Domain Computers fallback
        OR m.objectid ENDS WITH "S-1-5-11"       // Authenticated Users fallback
        OR m.objectid ENDS WITH "S-1-1-0"        // Everyone fallback
        OR m.objectid ENDS WITH "S-1-5-32-545")  // Users fallback
        """ + domain_filter_clause + """
        WITH m,
            CASE
                WHEN m.name STARTS WITH "DOMAIN USERS" OR m.objectid ENDS WITH "-513" THEN "Domain Users"
                WHEN m.name STARTS WITH "DOMAIN COMPUTERS" OR m.objectid ENDS WITH "-515" THEN "Domain Computers"
                WHEN m.name STARTS WITH "AUTHENTICATED USERS" OR m.objectid ENDS WITH "S-1-5-11" THEN "Authenticated Users"
                WHEN m.name STARTS WITH "EVERYONE" OR m.objectid ENDS WITH "S-1-1-0" THEN "Everyone"
                WHEN m.name STARTS WITH "USERS" OR m.objectid ENDS WITH "S-1-5-32-545" THEN "Users"
                ELSE "Other Groups"
            END AS groupFriendlyName

        // Part 1: Direct relationships (existing logic)
        OPTIONAL MATCH p=(m)-[r]->(n)
        WHERE n <> m AND
            // Only include interesting/exploitable relationships (excluding configured ones)
            (TYPE(r) IN """ + str(filtered_rels) + """ OR
            // Include MemberOf only if target is high-value
            (TYPE(r) = "MemberOf" AND n.highvalue = true)) AND (
            // Include any enabled object or non-computer object
            (NOT "Computer" IN LABELS(n) OR n.enabled = true) OR
            // Include disabled computers only if they have a write permission that could be used to enable them
            ("Computer" IN LABELS(n) AND n.enabled = false AND
              TYPE(r) IN ["Owns", "GenericAll", "GenericWrite", "WriteOwner", "WriteDacl"])
        )
        WITH m, p, n, groupFriendlyName,
            CASE
                WHEN p IS NOT NULL THEN
                    REDUCE(s = [], i IN RANGE(0, SIZE(NODES(p)) - 2) |
                        s + [NODES(p)[i].name, TYPE(RELATIONSHIPS(p)[i])]
                    )
                ELSE []
            END AS interleavedPath

        // Part 2: For MSSQL_Login targets, also fetch their database users
        // Match database users by serverLogin property since MSSQL_IsMappedTo edges may not exist
        // Use case-insensitive comparison as serverLogin/database names may have different casing
        WITH m, p, n, groupFriendlyName, interleavedPath
        OPTIONAL MATCH (dbUser:MSSQL_DatabaseUser)
        WHERE (CASE WHEN n:MSSQL_Login THEN toLower(dbUser.serverLogin) = toLower(n.name) AND n.SQLServer = dbUser.SQLServer ELSE false END)
        OPTIONAL MATCH (db:MSSQL_Database)
        WHERE db.SQLServer = dbUser.SQLServer AND toLower(db.name) = toLower(dbUser.database)
        WITH m, p, n, groupFriendlyName, interleavedPath, dbUser, db

        RETURN DISTINCT
            m.name AS `Source Group`,
            groupFriendlyName AS `Group Type`,
            m.objectid AS `Source Group SID`,
            m.distinguishedname AS `Source Group DN`,
            n.name AS `Target Object`,
            CASE
                WHEN "User" IN LABELS(n) THEN "User"
                WHEN "Computer" IN LABELS(n) THEN "Computer"
                WHEN "Group" IN LABELS(n) THEN "Group"
                WHEN "GPO" IN LABELS(n) THEN "GPO"
                WHEN "OU" IN LABELS(n) THEN "OU"
                WHEN "Domain" IN LABELS(n) THEN "Domain"
                // Older BloodHound exports can model certificate templates as :Base with a template DN.
                WHEN "Base" IN LABELS(n) AND n.distinguishedname =~ ".*CN=CERTIFICATE TEMPLATES.*" THEN "CertTemplate"
                WHEN "CertificateTemplate" IN LABELS(n) THEN "CertTemplate"
                ELSE "Unknown"
            END AS `Target Object Type`,
            n.objectid AS `Target Object SID`,
            n.distinguishedname AS `Target Object DN`,
            LABELS(n) AS `Target Object Types`,
            interleavedPath +
                CASE
                    WHEN p IS NOT NULL THEN [LAST(NODES(p)).name]
                    ELSE []
                END AS `Full Path`,
            CASE
                WHEN "Computer" IN LABELS(n) AND n.enabled = false THEN true
                ELSE false
            END AS `Is Disabled Computer`,
            n.SQLServer AS `Target SQL Server`,
            n.activeDirectoryPrincipal AS `Target AD Principal`,
            n.explicitPermissions AS `Target Permissions`,
            n.memberOfRoles AS `Target Roles`,
            n.defaultDatabase AS `Target Default Database`,
            dbUser.name AS `Database User Name`,
            dbUser.database AS `Database Name`,
            dbUser.memberOfRoles AS `Database Roles`,
            db.isTrustworthy AS `Database Is Trustworthy`,
            dbUser.explicitPermissions AS `Database User Permissions`
        """

        results = self.conn.query(query, name="get_builtin_groups_analysis")

        results_as_dicts = self._normalise_group_target_labels(
            [dict(record) for record in results]
        )

        target_sids = []
        target_names_to_sids = {}

        for record in results_as_dicts:
            target_sid = record.get('Target Object SID')
            target_name = record.get('Target Object')

            if target_sid:
                target_sids.append(target_sid)
                target_names_to_sids[target_name] = target_sid

        target_sids = list(set(target_sids))

        escalation_paths_by_sid = {}
        if target_sids:
            batch_size = 250
            for i in range(0, len(target_sids), batch_size):
                batch = target_sids[i:i+batch_size]

                batch_results = self._find_escalation_paths_v2(batch, interesting_rels_only=True)
                if batch_results is not None:
                    escalation_paths_by_sid.update(batch_results)

        for record in results_as_dicts:
            target_sid = record.get('Target Object SID')
            if target_sid and target_sid in escalation_paths_by_sid:
                paths = escalation_paths_by_sid[target_sid]
                has_escalation_path = any(p.get('hasEscalationPath', False) for p in paths)
                record['Target Has Escalation Path'] = has_escalation_path

                if has_escalation_path:
                    for path in paths:
                        if path.get('hasEscalationPath'):
                            full_path = path.get('fullPath', [])
                            # drop paths whose edges are in self.excluded_relationships
                            if self.excluded_relationships and full_path:
                                path_contains_excluded = False
                                for i in range(1, len(full_path), 2):
                                    if i < len(full_path) and full_path[i].upper() in self.excluded_relationships:
                                        path_contains_excluded = True
                                        break
                                if not path_contains_excluded:
                                    record['Target Escalation Path'] = full_path
                                    break
                            else:
                                record['Target Escalation Path'] = full_path
                                break
                    # filtering removed every path — record as no path
                    if 'Target Escalation Path' not in record:
                        record['Target Has Escalation Path'] = False
                        record['Target Escalation Path'] = []
                else:
                    record['Target Escalation Path'] = []
            else:
                record['Target Has Escalation Path'] = False
                record['Target Escalation Path'] = []

        self.builtin_groups_paths_cache = results_as_dicts
        return results_as_dicts

    def get_common_groups_analysis(self, threshold_count, total_user_count=None, force_refresh=False):
        # Retained for callers/tests that pin the threshold denominator; the Cypher only needs threshold_count.
        del total_user_count

        if not force_refresh and self.common_groups_paths_cache is not None:
            return self.common_groups_paths_cache

        interesting_rels = ["Owns", "GenericAll", "GenericWrite", "WriteOwner", "WriteDacl",
                           "AdminTo", "CanPSRemote", "CanRDP", "ForceChangePassword",
                           "AllExtendedRights", "AddMember", "AddSelf", "AllowedToDelegate", "AllowedToAct",
                           "AddAllowedToAct",
                           "DCSync", "ReadLAPSPassword", "ReadGMSAPassword", "SyncLAPSPassword",
                           "DumpSMSAPassword", "SQLAdmin",
                           "WriteSPN", "AddKeyCredentialLink", "WriteAccountRestrictions",
                           "GPLink", "WriteGPLink", "GoldenCert", "ManageCA", "ManageCertificates",
                           "CoerceToTGT", "CoerceAndRelayNTLMToADCS",
                           "CoerceAndRelayNTLMToSMB", "CoerceAndRelayNTLMToLDAP", "CoerceAndRelayNTLMToLDAPS",
                           "CoerceAndRelayToSMB", "CoerceAndRelayToAdminService",
                           "AbuseTGTDelegation", "CrossForestTrust"]

        filtered_rels = [rel for rel in interesting_rels if rel.upper() not in self.excluded_relationships]

        domain_filter_group = self._domain_condition("g")
        domain_filter_user = self._domain_condition("u")

        # Build admin group exclusion clause from the canonical list
        admin_exclusion_parts = [f'g.name STARTS WITH "{name}"' for name in ADMIN_GROUP_NAMES]
        admin_exclusion_clause = "AND NOT (" + " OR ".join(admin_exclusion_parts) + ")"

        query = """
        MATCH (g:Group)
        WHERE NOT (
            g.objectid ENDS WITH "-513"
            OR g.objectid ENDS WITH "-515"
            OR g.objectid ENDS WITH "S-1-5-11"
            OR g.objectid ENDS WITH "S-1-1-0"
            OR g.objectid ENDS WITH "S-1-5-32-545"
        )
        """ + admin_exclusion_clause + domain_filter_group + """

        WITH g
        MATCH (u:User)-[:MemberOf]->(g)
        WHERE u.enabled = true
        """ + domain_filter_user + """
        WITH g, count(DISTINCT u) AS memberCount
        WHERE memberCount >= $threshold_count

        OPTIONAL MATCH p=(g)-[r]->(n)
        WHERE n <> g AND
            (TYPE(r) IN """ + str(filtered_rels) + """ OR
            (TYPE(r) = "MemberOf" AND n.highvalue = true)) AND (
            (NOT "Computer" IN LABELS(n) OR n.enabled = true) OR
            ("Computer" IN LABELS(n) AND n.enabled = false AND
              TYPE(r) IN ["Owns", "GenericAll", "GenericWrite", "WriteOwner", "WriteDacl"])
        )
        WITH g, memberCount, p, n,
            CASE
                WHEN p IS NOT NULL THEN
                    REDUCE(s = [], i IN RANGE(0, SIZE(NODES(p)) - 2) |
                        s + [NODES(p)[i].name, TYPE(RELATIONSHIPS(p)[i])]
                    )
                ELSE []
            END AS interleavedPath

        RETURN DISTINCT
            g.name AS `Source Group`,
            g.name AS `Group Type`,
            memberCount AS `Member Count`,
            g.objectid AS `Source Group SID`,
            g.distinguishedname AS `Source Group DN`,
            n.name AS `Target Object`,
            CASE
                WHEN "User" IN LABELS(n) THEN "User"
                WHEN "Computer" IN LABELS(n) THEN "Computer"
                WHEN "Group" IN LABELS(n) THEN "Group"
                WHEN "GPO" IN LABELS(n) THEN "GPO"
                WHEN "OU" IN LABELS(n) THEN "OU"
                WHEN "Domain" IN LABELS(n) THEN "Domain"
                // Older BloodHound exports can model certificate templates as :Base with a template DN.
                WHEN "Base" IN LABELS(n) AND n.distinguishedname =~ ".*CN=CERTIFICATE TEMPLATES.*" THEN "CertTemplate"
                WHEN "CertificateTemplate" IN LABELS(n) THEN "CertTemplate"
                ELSE "Unknown"
            END AS `Target Object Type`,
            n.objectid AS `Target Object SID`,
            n.distinguishedname AS `Target Object DN`,
            LABELS(n) AS `Target Object Types`,
            interleavedPath +
                CASE
                    WHEN p IS NOT NULL THEN [LAST(NODES(p)).name]
                    ELSE []
                END AS `Full Path`,
            CASE
                WHEN "Computer" IN LABELS(n) AND n.enabled = false THEN true
                ELSE false
            END AS `Is Disabled Computer`
        """

        results = self.conn.query(query, parameters={'threshold_count': threshold_count}, name="get_common_groups_analysis")

        results_as_dicts = self._normalise_group_target_labels(
            [dict(record) for record in results]
        )

        # Enrich targets with onward escalation paths (same as builtin groups)
        target_sids = list({r.get('Target Object SID') for r in results_as_dicts if r.get('Target Object SID')})

        escalation_paths_by_sid = {}
        if target_sids:
            batch_size = 250
            for i in range(0, len(target_sids), batch_size):
                batch = target_sids[i:i+batch_size]
                batch_results = self._find_escalation_paths_v2(batch, interesting_rels_only=True)
                if batch_results is not None:
                    escalation_paths_by_sid.update(batch_results)

        for record in results_as_dicts:
            target_sid = record.get('Target Object SID')
            if target_sid and target_sid in escalation_paths_by_sid:
                paths = escalation_paths_by_sid[target_sid]
                has_escalation_path = any(p.get('hasEscalationPath', False) for p in paths)
                record['Target Has Escalation Path'] = has_escalation_path

                if has_escalation_path:
                    for path in paths:
                        if path.get('hasEscalationPath'):
                            full_path = path.get('fullPath', [])
                            if self.excluded_relationships and full_path:
                                path_contains_excluded = False
                                for idx in range(1, len(full_path), 2):
                                    if idx < len(full_path) and full_path[idx].upper() in self.excluded_relationships:
                                        path_contains_excluded = True
                                        break
                                if not path_contains_excluded:
                                    record['Target Escalation Path'] = full_path
                                    break
                            else:
                                record['Target Escalation Path'] = full_path
                                break
                    if 'Target Escalation Path' not in record:
                        record['Target Has Escalation Path'] = False
                        record['Target Escalation Path'] = []
                else:
                    record['Target Escalation Path'] = []
            else:
                record['Target Has Escalation Path'] = False
                record['Target Escalation Path'] = []

        self.common_groups_paths_cache = results_as_dicts
        return results_as_dicts

    def get_computer_admin_paths(self, force_refresh=False):
        cache_key = "admin_paths"

        if cache_key in self.admin_paths_cache and not force_refresh:
            return self.admin_paths_cache[cache_key]

        # Domain filtering for computers (FQDN format: HOSTNAME.DOMAIN)
        domain_filter_c1c2 = ""
        domain_filter_c3c4 = ""
        if self._domain_filter:
            domain_filter_c1c2 = self._domain_condition("c1") + self._domain_condition("c2")
            domain_filter_c3c4 = self._domain_condition("c3") + self._domain_condition("c4")

        query = """
            MATCH (c1:Computer)-[r:AdminTo]->(c2:Computer)
            WHERE c1.objectid <> c2.objectid
                AND c1.enabled = true
                AND c2.enabled = true""" + domain_filter_c1c2 + """
            RETURN c1.objectid AS SourceSID, c1.samaccountname AS SourceComputer, c1.name AS SourceFQDN,
                'DirectAdminTo' AS RelationshipType,
                c2.objectid AS TargetSID, c2.samaccountname AS TargetComputer, c2.name AS TargetFQDN
            UNION ALL
            MATCH (c1:Computer)-[r:AdminTo]->(c2:Computer)
            WHERE c1.objectid <> c2.objectid
                AND c1.enabled = true
                AND c2.enabled = true
                AND c2.smbsigning = false""" + domain_filter_c1c2 + """
            RETURN c1.objectid AS SourceSID, c1.samaccountname AS SourceComputer, c1.name AS SourceFQDN,
                'NTLMRelay(SMBSigningDisabled)' AS RelationshipType,
                c2.objectid AS TargetSID, c2.samaccountname AS TargetComputer, c2.name AS TargetFQDN
            UNION ALL
            MATCH (c3:Computer)-[:MemberOf]->(g:Group)-[:AdminTo]->(c4:Computer)
            WHERE c3.objectid <> c4.objectid
                AND c3.enabled = true
                AND c4.enabled = true""" + domain_filter_c3c4 + """
            RETURN c3.objectid AS SourceSID, c3.samaccountname AS SourceComputer, c3.name AS SourceFQDN,
                g.name + ' > AdminTo' AS RelationshipType,
                c4.objectid AS TargetSID, c4.samaccountname AS TargetComputer, c4.name AS TargetFQDN
            UNION ALL
            MATCH (c3:Computer)-[:MemberOf]->(g:Group)-[:AdminTo]->(c4:Computer)
            WHERE c3.objectid <> c4.objectid
                AND c3.enabled = true
                AND c4.enabled = true
                AND c4.smbsigning = false""" + domain_filter_c3c4 + """
            RETURN c3.objectid AS SourceSID, c3.samaccountname AS SourceComputer, c3.name AS SourceFQDN,
                g.name + ' > NTLMRelay(SMBSigningDisabled)' AS RelationshipType,
                c4.objectid AS TargetSID, c4.samaccountname AS TargetComputer, c4.name AS TargetFQDN
            ORDER BY SourceSID, TargetSID, RelationshipType
        """
        results = self.conn.query(query, name="get_computer_admin_paths")
        self.admin_paths_cache[cache_key] = results
        return results

    def get_user_to_computer_admin_paths(self, force_refresh=False):
        cache_key = "user_to_computer_paths"

        if cache_key in self.admin_paths_cache and not force_refresh:
            return self.admin_paths_cache[cache_key]

        domain_where = self._domain_condition("user") + self._domain_condition("computer")

        query = """
            MATCH (user:User)-[r:AdminTo]->(computer:Computer)
            WHERE user.enabled = true AND computer.enabled = true""" + domain_where + """
            RETURN user.objectid AS SourceSID, user.samaccountname AS SourceComputer, user.name AS SourceFQDN,
                'DirectAdminTo' AS RelationshipType,
                computer.objectid AS TargetSID, computer.samaccountname AS TargetComputer, computer.name AS TargetFQDN
        """
        results = self.conn.query(query, name="get_user_to_computer_admin_paths")
        self.admin_paths_cache[cache_key] = results
        return results
