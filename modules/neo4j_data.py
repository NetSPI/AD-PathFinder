import threading

from .domain_filter import DomainFilterMixin
from .neo4j_escalation import EscalationPathsMixin
from .neo4j_groups import GroupAnalysisMixin
from .hv_groups import admin_groups_for_domain
from .relationships import ESCALATION_RELS
from .node_type_cache import (
    AD_REPORT_LABELS,
    NON_REPORTABLE_NODE_LABELS,
    extract_ad_report_type_from_labels,
)

class Neo4jData(EscalationPathsMixin, GroupAnalysisMixin, DomainFilterMixin):


    def __init__(self, neo4j_conn, excluded_relationships=None, domain_filter=None, diagnostics=None):
        if diagnostics:
            from .neo4j_connection import InstrumentedConnection
            self.conn = InstrumentedConnection(neo4j_conn, diagnostics)
        else:
            self.conn = neo4j_conn
        self._diagnostics = diagnostics
        self.all_users_data_cache = None
        self.escalation_paths_cache = {}
        self.admin_paths_cache = {}
        self.builtin_groups_paths_cache = None
        self.common_groups_paths_cache = None
        self.admin_users_cache = None
        self._admin_users_set_upper = None
        self.admin_computers_cache = None
        self._hv_principal_sets_cache = {}
        self._hv_principal_sets_lock = threading.Lock()
        self._domain_filter = domain_filter.upper() if domain_filter else None
        self.excluded_relationships = [rel.upper() for rel in (excluded_relationships or [])]
        self._empty_pattern_notice_emitted = False

    def _notice_empty_relationship_pattern(self):
        if self._empty_pattern_notice_emitted:
            return
        self._empty_pattern_notice_emitted = True
        print(
            "Empty relationship pattern after [EXCLUSIONS] filtering — "
            "escalation queries skipped. Edit `[EXCLUSIONS] excluded_relationships` "
            "in config.ini if unintentional."
        )

    def _get_tier0_target_exclusion(self, target_var='g'):
        return f"""
        AND NOT ('OU' IN labels({target_var}))
        AND NOT ('Container' IN labels({target_var}))
        AND NOT (
            'EnterpriseCA' IN labels({target_var})
            AND NOT (
                EXISTS {{ MATCH ({target_var})<-[:HostsCAService]-(host:Computer) WHERE host.enabled = true }}
                AND EXISTS {{ MATCH ({target_var})-[:TrustedForNTAuth]->(:NTAuthStore) }}
                AND EXISTS {{ MATCH (:CertTemplate)-[:PublishedTo]->({target_var}) }}
            )
        )
        AND NOT (
            ('AIACA' IN labels({target_var}) OR 'RootCA' IN labels({target_var}))
            AND NOT EXISTS {{
                MATCH (activeca:EnterpriseCA)-[:EnterpriseCAFor]->({target_var})
                WHERE EXISTS {{ MATCH (activeca)<-[:HostsCAService]-(host:Computer) WHERE host.enabled = true }}
                AND EXISTS {{ MATCH (activeca)-[:TrustedForNTAuth]->(:NTAuthStore) }}
                AND EXISTS {{ MATCH (:CertTemplate)-[:PublishedTo]->(activeca) }}
            }}
        )
    """

    def check_bh_version(self):
        if hasattr(self, '_bh_version'):
            return self._bh_version
        query = """
        MATCH (n)
        WHERE n.system_tags IS NOT NULL
        RETURN count(n) > 0 AS is_v2
        """
        result = self.conn.query(query, name="check_bh_version")
        self._bh_version = "v2" if result and result[0]['is_v2'] else "v1"
        return self._bh_version

    def get_domain_name(self, force_refresh=False):
        if self._domain_filter:
            return self._domain_filter
        if not force_refresh and hasattr(self, '_domain_name_cache'):
            return self._domain_name_cache

        query = """
        MATCH (u:User)
        WITH u, SPLIT(u.name, "@") AS parts
        WHERE SIZE(parts) > 1
        RETURN DISTINCT parts[1] AS domain
        LIMIT 1
        """
        result = self.conn.query(query, name="get_domain_name")
        self._domain_name_cache = result[0]['domain'] if result else "Unknown Domain"
        return self._domain_name_cache

    def get_all_domain_names(self):
        query = """
        MATCH (u:User)
        WITH u, SPLIT(u.name, "@") AS parts
        WHERE SIZE(parts) > 1
        RETURN DISTINCT parts[1] AS domain
        """
        results = self.conn.query(query, name="get_all_domain_names")
        return [r['domain'] for r in results if r.get('domain')] if results else []

    def build_rid_to_domain_map(self):
        query = """
        MATCH (n)
        WHERE (n:User OR n:Computer) AND n.name IS NOT NULL AND n.name <> ''
        RETURN
            n.name AS full_name,
            n.objectid AS sid,
            CASE WHEN n:Computer THEN toLower(n.samaccountname) ELSE toLower(split(n.name, '@')[0]) END AS username
        """
        results = self.conn.query(query, name="build_rid_to_domain_map")
        rid_map = {}
        prefix_map = {}

        all_domains = self.get_all_domain_names()
        # longest first so sub-domains match before parents
        all_domains_sorted = sorted(all_domains, key=len, reverse=True)

        for record in results:
            full_name = record.get('full_name', '')
            sid = record.get('sid', '')
            username = record.get('username', '')
            if not full_name or not username:
                continue

            domain = None
            if '@' in full_name:
                domain = full_name.split('@', 1)[1]
            else:
                full_name_upper = full_name.upper()
                for d in all_domains_sorted:
                    if full_name_upper.endswith('.' + d.upper()):
                        domain = d
                        break
            if not domain:
                continue

            rid_str = None
            if sid and 'S-1-' in sid:
                rid_str = sid.rsplit('-', 1)[-1]

            username_lower = username.lower()
            domain_prefix = domain.upper().split('.')[0].lower()

            if rid_str:
                key = (username_lower, rid_str)
                if key not in rid_map:
                    rid_map[key] = []
                if domain not in rid_map[key]:
                    rid_map[key].append(domain)

            prefix_key = (domain_prefix, username_lower)
            prefix_map[prefix_key] = domain

        return rid_map, prefix_map
    
    def _is_admin_user(self, name):
        # based on group membership, not admincount
        if not name:
            return False
        name_upper = name.upper()
        if self._admin_users_set_upper is not None:
            return name_upper in self._admin_users_set_upper
        if self.admin_users_cache is not None:
            return name_upper in {n.upper() for n in self.admin_users_cache}
        return False

    def get_domain_sid_pattern(self):
        domain = self.get_domain_name()
        if domain and domain != "Unknown Domain":
            query = """
            MATCH (n:Group)
            WHERE n.name = $group_name
            RETURN n.objectid as sid
            LIMIT 1
            """
            results = self.conn.query(query, parameters={'group_name': f'DOMAIN USERS@{domain}'}, name="get_domain_sid_pattern")
            if results and results[0].get('sid'):
                domain_sid = results[0]['sid']
                sid_parts = domain_sid.split('-')
                if len(sid_parts) > 1:
                    return '-'.join(sid_parts[:-1])

        query = """
        MATCH (n:Group)
        WHERE n.name =~ '.*DOMAIN USERS.*'
        RETURN n.objectid as sid
        LIMIT 1
        """
        results = self.conn.query(query, name="get_domain_sid_pattern_fallback")
        if results and results[0].get('sid'):
            domain_sid = results[0]['sid']
            sid_parts = domain_sid.split('-')
            if len(sid_parts) > 1:
                return '-'.join(sid_parts[:-1])

        return None                            
    
    def update_user_passwords_by_sid(self, sid_to_password_map):
        if not sid_to_password_map:
            print("[-] No passwords to update in Neo4j")
            return 0
        
        print(f"[*] Updating {len(sid_to_password_map)} users/computers with passwords in Neo4j...")
        
        updates = [
            {
                'sid': sid,
                'password': password
            }
            for sid, password in sid_to_password_map.items()
        ]
        
        query = """
        UNWIND $updates AS update
        MATCH (n)
        WHERE (n:User OR n:Computer) AND n.objectid = update.sid
        SET n.password = update.password,
            n.owned = true
        WITH n, 
            CASE WHEN 'Computer' IN labels(n) THEN 1 ELSE 0 END as is_computer,
            CASE WHEN 'User' IN labels(n) THEN 1 ELSE 0 END as is_user
        RETURN sum(is_user) as users_updated, sum(is_computer) as computers_updated
        """
        
        try:
            results = self.conn.query(query, parameters={'updates': updates}, name="update_user_passwords_by_sid")
            if results:
                updated_users = results[0]['users_updated']
                updated_computers = results[0]['computers_updated']
                updated_count = updated_users + updated_computers
                print(f"[+] Successfully updated {updated_count} nodes with passwords ({updated_users} users, {updated_computers} computers)")
                return updated_count
            else:
                print("[-] No results returned from update query")
                return 0
        except Exception as e:
            print(f"[-] Error updating passwords: {e}")
            return 0
        
    def check_passwords_populated(self, account_analysis):
        if not hasattr(account_analysis, 'cracked_accounts') or not account_analysis.cracked_accounts:
            return (0, 0, 0)
        
        cracked_accounts_count = len(account_analysis.cracked_accounts)
        if cracked_accounts_count == 0:
            return (0, 0, 0)
        
        cracked_sids = []
        cracked_usernames = list(account_analysis.cracked_accounts.keys())

        if hasattr(account_analysis, 'user_details_mapping'):
            for username in cracked_usernames:
                user_details = account_analysis.user_details_mapping.get(username.lower())
                if user_details and user_details.get('sid'):
                    cracked_sids.append(user_details['sid'])
        
        if not cracked_sids:
            return (0, 0, 0)

        optimised_query = """
        MATCH (n)
        WHERE n.objectid IN $sids AND n.enabled = true
        RETURN 
            count(n) AS total_cracked,
            count(CASE WHEN n.password IS NOT NULL AND n.password <> '' THEN 1 END) AS with_passwords,
            count(CASE WHEN n.owned = true THEN 1 END) AS marked_owned
        """
        
        try:
            results = self.conn.query(optimised_query, parameters={'sids': cracked_sids}, name="check_passwords_populated")
            if results:
                result = results[0]
                return (
                    result.get('total_cracked', 0),
                    result.get('with_passwords', 0), 
                    result.get('marked_owned', 0)
                )
        except Exception as e:
            print(f"Error checking password population: {e}")
        
        return (0, 0, 0)
    
    def get_admin_users_and_computers(self, force_refresh=False):
        if not force_refresh and self.admin_users_cache is not None and self.admin_computers_cache is not None:
            return self.admin_users_cache, self.admin_computers_cache

        domain = self.get_domain_name()
        if not domain:
            return [], []
    
        high_value_groups = admin_groups_for_domain(domain)

        nested_query = """
        MATCH (n)-[:MemberOf*1..3]->(g:Group)
        WHERE g.name IN $group_names
        AND (n:User OR n:Computer OR n:Group)
        AND n.name IS NOT NULL
        RETURN DISTINCT
            n.name as name,
            g.name as group_name,
            CASE
                WHEN n:User THEN 'User'
                WHEN n:Computer THEN 'Computer'
                WHEN n:Group THEN 'Group'
            END as entity_type
        """
            
        results = self.conn.query(nested_query, parameters={'group_names': high_value_groups}, name="get_admin_users_direct_members")

        admin_users = set()
        admin_computers = set()
        nested_groups = set()
    
        for record in results:
            if record['entity_type'] == 'User':
                admin_users.add(record['name'])
            elif record['entity_type'] == 'Computer':
                admin_computers.add(record['name'])
            elif record['entity_type'] == 'Group':
                nested_groups.add(record['name'])
    
        if nested_groups:
            member_query = """
            MATCH (n)-[:MemberOf*1..3]->(g:Group)
            WHERE g.name IN $group_names
            AND (n:User OR n:Computer)
            AND n.name IS NOT NULL
            RETURN DISTINCT
                n.name as name,
                CASE
                    WHEN n:User THEN 'User'
                    WHEN n:Computer THEN 'Computer'
                END as entity_type
            """
            
            nested_results = self.conn.query(member_query, parameters={'group_names': list(nested_groups)}, name="get_admin_users_nested_members")

            for record in nested_results:
                if record['entity_type'] == 'User':
                    admin_users.add(record['name'])
                elif record['entity_type'] == 'Computer':
                    admin_computers.add(record['name'])
    
        self.admin_users_cache = list(admin_users)
        self.admin_computers_cache = list(admin_computers)

        return self.admin_users_cache, self.admin_computers_cache

    def get_enterprise_ca_status(self):
        if hasattr(self, '_enterprise_ca_status_cache'):
            return self._enterprise_ca_status_cache
        query = """
        MATCH (ca:EnterpriseCA)
        OPTIONAL MATCH (ca)<-[:HostsCAService]-(host:Computer)
        OPTIONAL MATCH (ca)-[:TrustedForNTAuth]->(nta:NTAuthStore)
        WITH ca, host.enabled AS hostEnabled, count(DISTINCT nta) > 0 AS ntAuth
        OPTIONAL MATCH (ct:CertTemplate)-[:PublishedTo]->(ca)
        WITH ca.objectid AS sid, hostEnabled, ntAuth, count(ct) AS tplCount
        RETURN sid, hostEnabled, ntAuth, tplCount
        """
        results = self.conn.query(query, name="get_enterprise_ca_status") or []
        status = {}
        for r in results:
            sid = r.get('sid')
            if not sid:
                continue
            host_ok = r.get('hostEnabled') is True
            nt_auth = r.get('ntAuth', False)
            tpl_count = r.get('tplCount', 0)
            status[sid] = {
                'active': host_ok and nt_auth and tpl_count > 0,
                'template_count': tpl_count,
            }
        self._enterprise_ca_status_cache = status
        return status

    def get_full_groups_for_sids(self, sids):
        if not sids:
            return {}
        sid_list = [s for s in set(sids) if s]
        if not sid_list:
            return {}
        query = """
        MATCH (n)
        WHERE n.objectid IN $sids
        OPTIONAL MATCH (n)-[:MemberOf*1..5]->(g:Group)
        WITH n, collect(DISTINCT g) AS allGroups
        OPTIONAL MATCH (n)-[:MemberOf]->(dg:Group)
        WITH n, allGroups, collect(DISTINCT dg.objectid) AS directGroupSIDs
        RETURN n.objectid AS sid,
               [grp IN allGroups WHERE grp IS NOT NULL |
                   toLower(split(grp.name, '@')[0])] AS groups,
               directGroupSIDs AS directGroupSIDs
        """
        results = self.conn.query(query, parameters={'sids': sid_list}, name="get_full_groups_for_sids")
        out = {}
        for row in results or []:
            sid = row.get('sid')
            if not sid:
                continue
            groups = [g for g in (row.get('groups') or []) if g]
            # SID-based fallback: add "domain computers" if a -515 SID is a direct group
            direct_sids = row.get('directGroupSIDs') or []
            if any(isinstance(s, str) and s.endswith('-515') for s in direct_sids):
                if 'domain computers' not in groups:
                    groups.append('domain computers')
            out[sid] = sorted(set(groups))
        return out

    def get_all_users_with_attributes(self, username=None, force_refresh=False):
        if username is None and not force_refresh and self.all_users_data_cache:
            return self.all_users_data_cache

        if username and self.all_users_data_cache and not force_refresh:
            username_lower = username.lower()
            for user in self.all_users_data_cache:
                if ((user.get('username') or '').lower() == username_lower or
                    (user.get('username_with_domain') or '').lower() == username_lower):
                    return [user]

        domain = self.get_domain_name()
        if not domain:
            print("Warning: No domain found. Cannot determine admin status.")
            domain = "UNKNOWN"

        admin_groups = admin_groups_for_domain(domain)

        if username:
            is_sid = username.startswith('S-1-') if username else False
            sid_match = "OR n.objectid = $username" if is_sid else ""
    
            query = f"""
            MATCH (n)
            WHERE (n:User OR n:Computer) AND n.name IS NOT NULL AND n.name <> ''
            AND (
                toLower(n.name) = $username OR
                toLower(n.samaccountname) = $username OR
                toLower(split(n.name, '@')[0]) = $username OR
                CASE WHEN n:Computer THEN toLower(n.name) + '$' = $username ELSE false END
                {sid_match}
            )
            OPTIONAL MATCH (n)-[:MemberOf]->(g:Group)
            WITH n, collect(DISTINCT toLower(split(g.name, '@')[0])) AS groups, collect(DISTINCT g.name) AS fullGroupNames,
                 collect(DISTINCT g.objectid) AS groupSIDs
            // Add SID-based fallback for domain computers detection only if not already present
            WITH n, groups + 
                CASE 
                    WHEN any(sid IN groupSIDs WHERE sid ENDS WITH "-515") AND NOT "domain computers" IN groups 
                    THEN ["domain computers"] 
                    ELSE [] 
                END AS groups,
                 fullGroupNames
            OPTIONAL MATCH (n)-[:MemberOf*1..3]->(adminGroup:Group)
            WHERE adminGroup.name IN $admin_groups
            WITH n, groups, fullGroupNames, count(DISTINCT adminGroup) > 0 AS isAdmin
            RETURN
                CASE
                    WHEN n:Computer THEN toLower(n.samaccountname)
                    ELSE toLower(split(n.name, '@')[0])
                END AS username,
                n.name AS username_with_domain,
                n.description AS description,
                n.enabled AS enabled,
                groups,
                n.pwdlastset AS passwordLastChanged,
                n.lastlogon AS lastLogon,
                n.dontreqpreauth AS asrepRoastable,
                n.hasspn AS kerberoastable,
                n.unconstraineddelegation AS unconstrainedDelegation,
                n.allowedtodelegate AS constrainedDelegation,
                n.objectid AS sid,
                n.distinguishedname AS distinguishedname,
                CASE WHEN n:Computer THEN true ELSE false END as is_computer,
                isAdmin
            """
            results = self.conn.query(query, parameters={'username': username.lower(), 'admin_groups': admin_groups}, name="get_single_user_with_attributes")
        else:
            print("Loading all user data from Neo4j database...")

            admin_group_query = """
            MATCH (n)-[:MemberOf*1..3]->(adminGroup:Group)
            WHERE adminGroup.name IN $admin_groups
            AND (n:User OR n:Computer) AND n.name IS NOT NULL AND n.name <> ''
            AND n.enabled = true
            RETURN DISTINCT n.name AS username_with_domain
            """
            admin_group_results = self.conn.query(admin_group_query, parameters={'admin_groups': admin_groups}, name="get_all_users_admin_groups")
            admin_users_set = {result['username_with_domain'] for result in admin_group_results if result['username_with_domain']}
            self._admin_users_set_upper = {name.upper() for name in admin_users_set}

            query = """
            MATCH (n)
            WHERE (n:User OR n:Computer) AND n.name IS NOT NULL AND n.name <> ''
            OPTIONAL MATCH (n)-[:MemberOf]->(g:Group)
            WITH n, collect(DISTINCT toLower(split(g.name, '@')[0])) AS groups,
                 collect(DISTINCT g.objectid) AS groupSIDs
            // Add SID-based fallback for domain computers detection only if not already present
            WITH n, groups + 
                CASE 
                    WHEN any(sid IN groupSIDs WHERE sid ENDS WITH "-515") AND NOT "domain computers" IN groups 
                    THEN ["domain computers"] 
                    ELSE [] 
                END AS groups
            RETURN
                CASE
                    WHEN n:Computer THEN toLower(n.samaccountname)
                    ELSE toLower(split(n.name, '@')[0])
                END AS username,
                n.name AS username_with_domain,
                n.description AS description,
                n.enabled AS enabled,
                groups,
                n.pwdlastset AS passwordLastChanged,
                n.lastlogon AS lastLogon,
                n.dontreqpreauth AS asrepRoastable,
                n.hasspn AS kerberoastable,
                n.unconstraineddelegation AS unconstrainedDelegation,
                n.allowedtodelegate AS constrainedDelegation,
                n.objectid AS sid,
                n.distinguishedname AS distinguishedname,
                CASE WHEN n:Computer THEN true ELSE false END as is_computer
            ORDER BY n.name
            """
            results = self.conn.query(query, name="get_all_users_with_attributes")

            converted_results = []
            for result in results:
                result_dict = dict(result)
                username_with_domain = result_dict.get('username_with_domain', '')
                result_dict['isAdmin'] = username_with_domain in admin_users_set
                converted_results.append(result_dict)

            results = converted_results

        if not hasattr(self, 'sid_to_username'):
            self.sid_to_username = {}
            self.username_to_sid = {}
            self.computer_sids = set()
            self.user_sids = set()
    
        processed_results = []
    
        for record in results:
            user_dict = dict(record) if record else {}

            username_with_domain = user_dict.get('username_with_domain', '')

            raw_username = user_dict.get('username')

            if raw_username is None:
                if username_with_domain and '@' in username_with_domain:
                    try:
                        username_rec = username_with_domain.split('@')[0].lower()
                    except (AttributeError, IndexError):
                        username_rec = ''
                else:
                    username_rec = ''
            else:
                try:
                    username_rec = str(raw_username).lower()
                except (TypeError, AttributeError):
                    username_rec = ''
    
            sid_rec = user_dict.get('sid')

            if sid_rec and username_rec:
                self.sid_to_username[sid_rec] = username_rec
                self.username_to_sid[username_rec] = sid_rec

            is_computer = user_dict.get('is_computer', False)

            if not is_computer and username_rec:
                ends_with_dollar = (
                    username_rec.endswith('$') or
                    (username_with_domain and username_with_domain.endswith('$'))
                )

                # $-suffix = computer/gMSA; user in Domain Computers without $ is a mis-grouping
                if ends_with_dollar:
                    is_computer = True
                else:
                    is_computer = False

            user_dict['is_computer'] = is_computer

            if sid_rec:
                if is_computer:
                    self.computer_sids.add(sid_rec)
                else:
                    self.user_sids.add(sid_rec)

            if username_rec:
                processed_results.append(user_dict)

        if self._domain_filter and not username:
            # endswith('TRAINING.LOCAL') would also match SECRET.TRAINING.LOCAL
            all_known_domains = self.get_all_domain_names() if not hasattr(self, '_all_domain_names_cache') else self._all_domain_names_cache
            self._all_domain_names_cache = all_known_domains
            sub_domains_upper = {
                d.upper() for d in all_known_domains
                if d.upper() != self._domain_filter and d.upper().endswith('.' + self._domain_filter)
            }

            def _belongs_to_domain(uwd):
                uwd_upper = uwd.upper()
                # User format: USER@DOMAIN
                if uwd_upper.endswith(f"@{self._domain_filter}"):
                    return True
                # Computer format: HOST.DOMAIN — must not match a more-specific sub-domain
                if uwd_upper.endswith(f".{self._domain_filter}"):
                    for sd in sub_domains_upper:
                        if uwd_upper.endswith('.' + sd) or uwd_upper.endswith('@' + sd):
                            return False
                    return True
                return False

            processed_results = [
                u for u in processed_results
                if _belongs_to_domain(u.get('username_with_domain', ''))
            ]

        if not username:

            self.all_users_data_cache = processed_results

        return processed_results

    def populate_group_sid_mappings(self):
        if not hasattr(self, 'sid_to_username'):
            self.sid_to_username = {}
            self.username_to_sid = {}
            self.computer_sids = set()
            self.user_sids = set()

        rows = self.conn.query(
            "MATCH (g:Group) WHERE g.objectid IS NOT NULL AND g.name IS NOT NULL "
            "RETURN g.objectid AS sid, g.name AS name",
            name="populate_group_sid_mappings"
        )
        for row in rows:
            sid = row.get('sid')
            name = row.get('name')
            if sid and name:
                self.sid_to_username.setdefault(sid, name)

    def get_domain_properties_filtered(self):
        if hasattr(self, '_domain_properties_filtered_cache'):
            return dict(self._domain_properties_filtered_cache)

        query = """
        MATCH (d:Domain {name: $domain})
        RETURN properties(d) AS domainProperties
        """
        results = self.conn.query(
            query,
            parameters={'domain': self.get_domain_name()},
            name="get_domain_properties_filtered",
        )

        filtered = {}
        if results and results[0].get('domainProperties'):
            props = results[0]['domainProperties']
            for key in (
                'maxpwdage', 'minpwdage', 'minpwdlength', 'pwdhistorylength',
                'lockoutthreshold', 'lockoutduration', 'lockoutobservationwindow',
                'machineaccountquota',
            ):
                v = props.get(key)
                if v is None:
                    continue
                if isinstance(v, (int, float)) and abs(v) > 999_999_999:
                    continue
                filtered[key] = v

        self._domain_properties_filtered_cache = filtered
        return dict(filtered)

    def get_krbtgt_password_last_changed(self):
        if hasattr(self, '_krbtgt_pwd_last_changed_cache'):
            return self._krbtgt_pwd_last_changed_cache
        # KRBTGT is usually disabled — query without enabled filter
        domain_condition = self._domain_condition("n")

        query = f"""
        MATCH (n:User)
        WHERE toLower(n.samaccountname) = 'krbtgt'{domain_condition}
        RETURN n.pwdlastset AS pwdLastSet
        LIMIT 1
        """
        try:
            result = self.conn.query(query, name="get_krbtgt_password_last_changed")
            self._krbtgt_pwd_last_changed_cache = result[0].get('pwdLastSet') if result else None
        except Exception:
            self._krbtgt_pwd_last_changed_cache = None
        return self._krbtgt_pwd_last_changed_cache

    def get_object_details_by_sids(self, object_sids_list):
        if not object_sids_list:
            return []

        actual_sids = []
        names_for_lookup = []

        for item in object_sids_list:
            if item and isinstance(item, str):
                if item.startswith('S-1-'):
                    actual_sids.append(item)
                else:
                    names_for_lookup.append(item)

        all_results = []

        if actual_sids:
            chunk_size = 250
            for i in range(0, len(actual_sids), chunk_size):
                chunk = actual_sids[i:i+chunk_size]

                query = """
                UNWIND $sids AS objectSid
                MATCH (n)
                WHERE n.objectid = objectSid
                WITH objectSid, n,
                     CASE
                         WHEN any(label IN labels(n) WHERE label IN $ad_labels) THEN 0
                         WHEN any(label IN labels(n)
                                  WHERE NOT label IN $metadata_labels
                                  AND NOT label STARTS WITH 'Tag_') THEN 1
                         ELSE 2
                     END AS label_rank
                ORDER BY objectSid, label_rank
                WITH objectSid, collect(n)[0] AS n
                RETURN DISTINCT
                    n.name AS name,
                    n.samaccountname AS samaccountname,
                    n.objectid AS sid,
                    n.distinguishedname AS dn,
                    n.displayname AS displayname,
                    labels(n) AS all_types
                """

                try:
                    chunk_results = self.conn.query(
                        query,
                        parameters={
                            'sids': chunk,
                            'ad_labels': list(AD_REPORT_LABELS),
                            'metadata_labels': list(NON_REPORTABLE_NODE_LABELS),
                        },
                        name="get_object_details_by_sids",
                    )
                    if chunk_results:
                        all_results.extend(chunk_results)
                except Exception as e:
                    print(f"Warning: chunk SID lookup failed ({len(chunk)} sids): {e}")
                    if self._diagnostics:
                        self._diagnostics.record_error("get_object_details_by_sids", e)

        if names_for_lookup:
            name_results = self.get_object_details_by_name(names_for_lookup)
            all_results.extend(name_results)

        result_list = []
        for record in all_results:
            if not record:
                continue

            found_labels = record.get('all_types', [])
            best_type = extract_ad_report_type_from_labels(found_labels)

            clean_record = {
                'name': record.get('name') or record.get('displayname'),
                'samaccountname': record.get('samaccountname'),
                'sid': record.get('sid'),
                'dn': record.get('dn'),
                'type': best_type
            }

            result_list.append(clean_record)

        return result_list

    def get_all_computers_with_attributes(self, force_refresh=False):
        # Also picks up gMSA accounts (User nodes ending with $)
        if not force_refresh and hasattr(self, 'all_computers_cache') and self.all_computers_cache is not None:
            return self.all_computers_cache

        domain_where = self._domain_condition("c")

        query = """
        MATCH (c)
        WHERE c.enabled = true AND c.name IS NOT NULL
        AND (c:Computer OR c.samaccountname ENDS WITH '$' OR c.name ENDS WITH '$')""" + domain_where + """
        RETURN c.name AS name,
               c.samaccountname AS samaccountname,
               c.operatingsystem AS operatingsystem,
               c.smbsigning AS smbsigning,
               c.webclientrunning AS webclientrunning,
               c.objectid AS sid,
               c.description AS description,
               c.unconstraineddelegation AS unconstrainedDelegation,
               c.allowedtodelegate AS constrainedDelegation,
               c.isdc AS isDomainController,
               c.ldapsigning AS ldapSigning,
               CASE WHEN c:Computer THEN true ELSE false END as is_computer
        ORDER BY c.name
        """

        self.all_computers_cache = self.conn.query(query, name="get_all_computers_with_attributes")
        return self.all_computers_cache

    def get_entity_counts(self):
        # Not from the caches: computers is enabled-only, users mixes in Computer nodes
        query = """
        MATCH (n)
        WHERE (n:User OR n:Computer) AND n.name IS NOT NULL""" + self._domain_condition("n") + """
        RETURN CASE WHEN n:Computer THEN 'computers' ELSE 'users' END AS kind,
               count(*) AS total,
               sum(CASE WHEN n.enabled = true THEN 1 ELSE 0 END) AS enabled,
               sum(CASE WHEN n.enabled = false THEN 1 ELSE 0 END) AS disabled,
               sum(CASE WHEN n:Computer AND n.isdc = true THEN 1 ELSE 0 END) AS domain_controllers,
               sum(CASE WHEN n:Computer AND n.unconstraineddelegation = true THEN 1 ELSE 0 END) AS unconstrained_delegation
        """
        counts = {}
        for r in self.conn.query(query, name="get_entity_counts") or []:
            row = dict(r)
            kind = row.pop('kind')
            if kind == 'users':
                del row['domain_controllers'], row['unconstrained_delegation']
            counts[kind] = row
        return counts

    def get_all_enterprise_cas_with_attributes(self, force_refresh=False):
        if not force_refresh and hasattr(self, 'all_enterprise_cas_cache') and self.all_enterprise_cas_cache is not None:
            return self.all_enterprise_cas_cache

        # Enterprise CAs are forest-wide objects — their domain property is always the
        # forest root, not the subdomain hosting them. Filter by dnshostname instead.
        query = """
        MATCH (ca:EnterpriseCA)
        RETURN ca.name AS name,
               ca.dnshostname AS dnshostname,
               ca.caname AS caname,
               ca.domain AS domain,
               ca.objectid AS sid,
               ca.hasvulnerableendpoint AS hasvulnerableendpoint,
               ca.httpenrollmentendpoints AS httpenrollmentendpoints,
               ca.httpsenrollmentendpoints AS httpsenrollmentendpoints
        ORDER BY ca.name
        """

        result = self.conn.query(query, name="get_all_enterprise_cas")
        result = result if result is not None else []

        if self._domain_filter and result:
            df = self._domain_filter.upper()
            filtered = []
            for ca in result:
                hostname = (ca.get('dnshostname') or '').upper()
                # Extract domain from hostname: "SERVER.DOMAIN.COM" -> "DOMAIN.COM"
                dot_pos = hostname.find('.')
                if dot_pos >= 0 and hostname[dot_pos + 1:] == df:
                    filtered.append(ca)
            result = filtered

        self.all_enterprise_cas_cache = result
        return self.all_enterprise_cas_cache

    def get_bad_successor_ou_privileges(self, force_refresh=False):
        if not force_refresh and hasattr(self, 'bad_successor_cache') and self.bad_successor_cache is not None:
            return self.bad_successor_cache

        dc_domain = self._domain_condition("dc")
        target_domain = self._domain_condition("target")

        badsuccessor_query = f"""
        MATCH (dc:Computer)-[:MemberOf*1..]->(g:Group)
        WHERE dc.operatingsystem =~ '(?i).*WINDOWS SERVER 2025.*'
          AND g.name =~ '(?i).*DOMAIN CONTROLLERS.*'
          AND dc.enabled = true{dc_domain}
        WITH count(DISTINCT dc) > 0 AS has2025DC
        WHERE has2025DC = true
        
        MATCH (target)<-[r:WriteDacl|Owns|GenericAll|WriteOwner]-(n)
        WHERE (target:OU OR target:Container){target_domain}
          AND (n:User OR n:Computer OR n:Group)
          AND NOT ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0')
          AND COALESCE(n.enabled, true) = true
        RETURN CASE WHEN target:OU THEN 'OU' ELSE 'Container' END AS target_type,
               coalesce(target.name, target.objectid, 'Unknown') AS target_name,
               coalesce(n.name, n.objectid, 'Unknown') AS entity_name,
               target.objectid AS target_id,
               n.objectid AS entity_id,
               type(r) AS relationship_type
        """
        
        result = self.conn.query(badsuccessor_query, name="get_bad_successor_ou_privileges")

        self.bad_successor_cache = result if result is not None else []
        return self.bad_successor_cache

    def get_all_relationships(self, exclude_mssql=False):
        cache_attr = '_ad_only_relationships_pattern' if exclude_mssql else '_all_relationships_pattern'

        if hasattr(self, cache_attr):
            return getattr(self, cache_attr)

        query = """
        CALL db.relationshipTypes() YIELD relationshipType
        RETURN collect(relationshipType) as relationships
        """

        results = self.conn.query(query, name="get_all_relationships")
        if results and results[0].get('relationships'):
            relationships = results[0]['relationships']

            if self.excluded_relationships:
                excluded_set = set(self.excluded_relationships)
                relationships = [rel for rel in relationships if rel.upper() not in excluded_set]

            if exclude_mssql:
                relationships = [rel for rel in relationships if not rel.startswith('MSSQL_')]

            pattern = "|".join(relationships)
            if not pattern:
                self._notice_empty_relationship_pattern()
            setattr(self, cache_attr, pattern)
            return pattern

        setattr(self, cache_attr, "")
        return ""
    
    def get_interesting_relationships(self):
        if self.excluded_relationships:
            filtered_rels = [rel for rel in ESCALATION_RELS if rel.upper() not in self.excluded_relationships]
        else:
            filtered_rels = ESCALATION_RELS

        pattern = "|".join(filtered_rels)
        if not pattern:
            self._notice_empty_relationship_pattern()
        return pattern
