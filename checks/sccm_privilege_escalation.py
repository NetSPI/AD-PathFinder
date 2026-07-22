from checks.core import Check, check
from checks.core.high_value import high_value_principal_sets_for_check, is_high_value_principal
from checks.core.mssql_common import (
    MSSQL_ABUSE_EDGES,
    linked_server_target_resolution,
    primary_label_expr,
    sql_login_holder_parameters,
    sql_login_report_holder_expr,
    sql_login_report_holder_filter,
)
from checks.core.platform_mixins import MSSQLDomainMixin, SCCMDomainMixin


_SCCM_PATH_EDGES = [
    'MemberOf', *MSSQL_ABUSE_EDGES,
    'SCCM_IsMappedTo', 'SCCM_AllPermissions', 'SCCM_IsAssigned',
]

_LINKED_PRE_EDGES = [
    'MSSQL_ExecuteAs', 'MSSQL_Impersonate',
    'MSSQL_Connect', 'MSSQL_ConnectAnyDatabase',
]

_SERVER_REACH_EDGES = [
    'MSSQL_Connect', 'MSSQL_ConnectAnyDatabase',
]

_ASSUME_ROLE_EDGES = [
    'MSSQL_ExecuteAs', 'MSSQL_Impersonate',
]

_SERVER_CONTROL_EDGES = [
    'MSSQL_ControlServer', 'MSSQL_AlterAnyLogin',
    'MSSQL_AlterAnyServerRole', 'MSSQL_GrantAnyPermission',
    'MSSQL_ImpersonateAnyLogin', 'MSSQL_ExecuteAsOwner',
]

_HIGH_VALUE_SERVER_ROLES = [
    'SYSADMIN', 'SECURITYADMIN', 'SERVERADMIN', 'SETUPADMIN',
]

_HIGH_VALUE_DB_ROLES = [
    'db_owner', 'db_securityadmin', 'db_accessadmin', 'db_ddladmin',
]

_HIGH_VALUE_DB_PERMS = [
    'CONTROL', 'ALTER DATABASE',
]

_SYSADMIN_SUBORDINATES = {
    'SECURITYADMIN', 'SERVERADMIN', 'SETUPADMIN',
}

_DB_OWNER_SUBORDINATES = {
    'DB_SECURITYADMIN', 'DB_ACCESSADMIN', 'DB_DDLADMIN',
}

_PRIVILEGED_SCCM_ROLES = [
    'FULL ADMINISTRATOR', 'INFRASTRUCTURE ADMINISTRATOR',
]

@check(risk="Critical", category="SCCM Privilege Escalation", entity="user",
       data=[], requires=["mssql", "sccm"], display="shared_graph_paths")
class SCCMPrivilegeEscalationCheck(MSSQLDomainMixin, SCCMDomainMixin, Check):

    def execute(self):
        high_value_users, high_value_computers, high_value_groups = (
            high_value_principal_sets_for_check(
                self,
                query_name="sccm_privilege_escalation_high_value_principals",
            )
        )

        sccm_paths = self._fetch_sccm_paths()
        if not sccm_paths:
            return {}

        by_principal = {}
        for path in sccm_paths:
            sid = path.get('principal_sid')
            if not sid:
                continue

            name = (path.get('principal_name') or '').upper()
            ptype = path.get('principal_type') or ''

            if is_high_value_principal(
                name,
                ptype,
                high_value_users,
                high_value_computers,
                high_value_groups,
            ):
                continue

            by_principal.setdefault(sid, []).append(path)

        results = {}
        for sid, paths in by_principal.items():
            lines = self._format_principal(paths)
            if lines:
                results[sid] = self.finding("\n".join(lines))

        return results

    def _fetch_sccm_paths(self):
        return (
            self._fetch_pure_sccm_paths()
            + self._fetch_sql_to_sccm_paths()
            + self._fetch_server_control_paths()
            + self._fetch_linked_sccm_paths()
            + self._fetch_linked_execute_host_sccm_paths()
            + self._fetch_coercion_paths()
            + self._fetch_service_account_paths()
        )

    def _fetch_pure_sccm_paths(self):
        domain_cond = self._domain_condition("principal")
        site_cond = self._site_domain_condition("site")

        site_rows = self.query(f"""
            MATCH p = (principal)-[:MemberOf*0..6]->(holder)
                      -[:SCCM_IsMappedTo]->(adminUser:SCCM_AdminUser)
                      -[:SCCM_AllPermissions]->(site:SCCM_Site)
            WHERE (principal:User OR principal:Computer){domain_cond}
              AND (NOT principal:Computer OR coalesce(principal.enabled, true) = true)
              AND true{site_cond}
            RETURN DISTINCT
                   principal.objectid AS principalSid,
                   principal.name AS principalName,
                   CASE WHEN principal:Computer THEN 'Computer' ELSE 'User' END AS principalType,
                   coalesce(site.siteCode, site.displayName, site.objectid) AS targetName,
                   'SCCM_Site' AS targetType,
                   null AS databaseName,
                   null AS serverName,
                   [rel IN relationships(p) | type(rel)] AS pathEdges,
                   length(p) AS pathLength,
                   {self._path_node_names_expr('nodes(p)')} AS pathNodeNames,
                   null AS sccmImpactDb,
                   null AS sccmImpactSite
        """, name="sccm_pure_site_paths")

        role_rows = self.query(f"""
            MATCH (site:SCCM_Site)
            WHERE true{site_cond}
            WITH collect(DISTINCT site.siteCode) AS siteCodes
            MATCH p = (principal)-[:MemberOf*0..6]->(holder)
                      -[:SCCM_IsMappedTo]->(adminUser:SCCM_AdminUser)
                      -[:SCCM_IsAssigned]->(role:SCCM_SecurityRole)
            WHERE (principal:User OR principal:Computer){domain_cond}
              AND (NOT principal:Computer OR coalesce(principal.enabled, true) = true)
              AND adminUser.sourceSiteCode IN siteCodes
              AND toUpper(role.name) IN $_privileged_sccm_roles
            RETURN DISTINCT
                   principal.objectid AS principalSid,
                   principal.name AS principalName,
                   CASE WHEN principal:Computer THEN 'Computer' ELSE 'User' END AS principalType,
                   coalesce(adminUser.name, adminUser.objectid) AS targetName,
                   'SCCM_AdminUser' AS targetType,
                   null AS databaseName,
                   null AS serverName,
                   [rel IN relationships(p) | type(rel)] AS pathEdges,
                   length(p) AS pathLength,
                   {self._path_node_names_expr('nodes(p)')} AS pathNodeNames,
                   null AS sccmImpactDb,
                   null AS sccmImpactSite
        """, parameters={
            "_privileged_sccm_roles": _PRIVILEGED_SCCM_ROLES,
        }, name="sccm_pure_role_paths")
        return self._path_rows(list(site_rows) + list(role_rows))

    def _fetch_sql_to_sccm_paths(self):
        domain_cond = self._domain_condition("principal")
        holder_domain_cond = self._domain_condition("holder")
        candidate_domain_cond = self._domain_condition("candidatePrincipal")
        member_domain_cond = self._domain_condition("memberPrincipal")
        site_cond = self._site_domain_condition("site")
        impact_site_cond = self._site_domain_condition("impactSite")

        rows = self.query(f"""
            MATCH (sccmDb:MSSQL_Database)-[:SCCM_AssignAllPermissions]->(site:SCCM_Site)
            WHERE true{site_cond}
            MATCH (sccmServer:MSSQL_Server {{name: sccmDb.SQLServer}})
            WITH collect(DISTINCT sccmServer) AS sccmServers,
                 collect(DISTINCT sccmDb) AS sccmDbs

            MATCH (target)
            WHERE
              (target:MSSQL_ServerRole
                  AND toUpper(target.name) IN $_high_value_server_roles
                  AND ANY(srv IN sccmServers WHERE target.SQLServer = srv.name))
              OR (target:MSSQL_DatabaseRole
                  AND toLower(split(target.name, '@')[0]) IN $_high_value_db_roles
                  AND EXISTS {{
                    MATCH (db:MSSQL_Database)-[:MSSQL_Contains]->(target)
                    WHERE db IN sccmDbs
                  }})
              OR (target:MSSQL_DatabaseUser
                  AND target.explicitPermissions IS NOT NULL
                  AND ANY(perm IN target.explicitPermissions
                          WHERE toUpper(perm) IN $_high_value_db_perms)
                  AND EXISTS {{
                    MATCH (db:MSSQL_Database)-[:MSSQL_Contains]->(target)
                    WHERE db IN sccmDbs
                  }})

            MATCH (holder)-[:MSSQL_HasLogin]->(startLogin:MSSQL_Login)
            WHERE holder:User OR holder:Computer OR holder:Group

            WITH holder, startLogin, target,
                 {sql_login_report_holder_expr()} AS reportHolder
            {sql_login_report_holder_filter(holder_domain_cond, candidate_domain_cond)}
            MATCH p = shortestPath((startLogin)-[rels*1..6]->(target))
            WHERE ALL(rel IN rels WHERE type(rel) IN $_sccm_path_edges)

            OPTIONAL MATCH (db:MSSQL_Database)-[:MSSQL_Contains]->(target)
            OPTIONAL MATCH (impactDb:MSSQL_Database)-[:SCCM_AssignAllPermissions]->(impactSite:SCCM_Site)
            WHERE true{impact_site_cond}
              AND (
                (target:MSSQL_ServerRole AND impactDb.SQLServer = target.SQLServer)
                OR ((target:MSSQL_DatabaseRole OR target:MSSQL_DatabaseUser)
                    AND EXISTS {{ MATCH (impactDb)-[:MSSQL_Contains]->(target) }})
              )
            OPTIONAL MATCH memberPath = (memberPrincipal)-[:MemberOf*1..6]->(holder)
            WHERE holder:Group AND NOT reportHolder
              AND (memberPrincipal:User OR memberPrincipal:Computer){member_domain_cond}
            WITH CASE
                     WHEN reportHolder OR holder:User OR holder:Computer THEN holder
                     ELSE memberPrincipal
                 END AS principal,
                 holder, startLogin, target, db, impactDb, impactSite, p, rels, reportHolder, memberPath
            WHERE principal IS NOT NULL
              AND (reportHolder OR principal:User OR principal:Computer){domain_cond}
              AND (NOT principal:Computer OR coalesce(principal.enabled, true) = true)

            RETURN DISTINCT
                   CASE WHEN reportHolder THEN holder.objectid ELSE principal.objectid END AS principalSid,
                   CASE WHEN reportHolder THEN holder.name ELSE principal.name END AS principalName,
                   CASE
                     WHEN reportHolder THEN 'Group'
                     WHEN principal:Computer THEN 'Computer'
                     ELSE 'User'
                   END AS principalType,
                   target.name AS targetName,
                   CASE
                     WHEN target:MSSQL_ServerRole THEN 'MSSQL_ServerRole'
                     WHEN target:MSSQL_DatabaseRole THEN 'MSSQL_DatabaseRole'
                     WHEN target:MSSQL_DatabaseUser THEN 'MSSQL_DatabaseUser'
                     WHEN target:MSSQL_Base THEN 'MSSQL'
                     WHEN target:SCCM_Base THEN 'SCCM'
                     ELSE coalesce({primary_label_expr('target')}, 'Unknown')
                   END AS targetType,
                   db.name AS databaseName,
                   target.SQLServer AS serverName,
                   CASE
                     WHEN reportHolder THEN ['MSSQL_HasLogin'] + [rel IN rels | type(rel)]
                     WHEN holder:Group AND memberPath IS NOT NULL
                         THEN [rel IN relationships(memberPath) | type(rel)] + ['MSSQL_HasLogin'] + [rel IN rels | type(rel)]
                     ELSE [rel IN rels | type(rel)]
                   END AS pathEdges,
                   CASE
                     WHEN reportHolder THEN length(p) + 1
                     WHEN holder:Group AND memberPath IS NOT NULL THEN length(memberPath) + length(p) + 1
                     ELSE length(p)
                   END AS pathLength,
                   CASE
                     WHEN reportHolder THEN [split(coalesce(holder.name, ''), '@')[0]] + {self._path_node_names_expr('nodes(p)')}
                     WHEN holder:Group AND memberPath IS NOT NULL
                         THEN {self._path_node_names_expr('nodes(memberPath)')} + {self._path_node_names_expr('nodes(p)')}
                     ELSE {self._path_node_names_expr('nodes(p)')}
                   END AS pathNodeNames,
                   impactDb.name AS sccmImpactDb,
                   impactSite.siteCode AS sccmImpactSite
        """, parameters={
            "_sccm_path_edges": _SCCM_PATH_EDGES,
            "_high_value_server_roles": _HIGH_VALUE_SERVER_ROLES,
            "_high_value_db_roles": _HIGH_VALUE_DB_ROLES,
            "_high_value_db_perms": _HIGH_VALUE_DB_PERMS,
            **sql_login_holder_parameters(),
        }, name="sccm_sql_target_paths")
        return self._path_rows(rows)

    def _fetch_server_control_paths(self):
        domain_cond = self._domain_condition("principal")
        holder_domain_cond = self._domain_condition("holder")
        candidate_domain_cond = self._domain_condition("candidatePrincipal")
        member_domain_cond = self._domain_condition("memberPrincipal")
        site_cond = self._site_domain_condition("site")

        rows = self.query(f"""
            MATCH (holder)-[:MSSQL_HasLogin]->(startLogin:MSSQL_Login)
            WHERE holder:User OR holder:Computer OR holder:Group

            WITH holder, startLogin,
                 {sql_login_report_holder_expr()} AS reportHolder
            {sql_login_report_holder_filter(holder_domain_cond, candidate_domain_cond)}
            MATCH (sccmDb:MSSQL_Database)-[:SCCM_AssignAllPermissions]->(site:SCCM_Site)
            WHERE true{site_cond}
            MATCH (sccmServer:MSSQL_Server {{name: sccmDb.SQLServer}})

            MATCH (predecessor)-[controlRel]->(sccmServer)
            WHERE type(controlRel) IN $_server_control_edges

            WITH holder, startLogin, sccmServer, sccmDb, site, predecessor, controlRel, reportHolder
            MATCH p = shortestPath((startLogin)-[rels*0..5]->(predecessor))
            WHERE ALL(rel IN rels WHERE type(rel) IN $_sccm_path_edges)

            OPTIONAL MATCH memberPath = (memberPrincipal)-[:MemberOf*1..6]->(holder)
            WHERE holder:Group AND NOT reportHolder
              AND (memberPrincipal:User OR memberPrincipal:Computer){member_domain_cond}
            WITH CASE
                     WHEN reportHolder OR holder:User OR holder:Computer THEN holder
                     ELSE memberPrincipal
                 END AS principal,
                 holder, sccmServer, sccmDb, site, p, rels, controlRel, reportHolder, memberPath
            WHERE principal IS NOT NULL
              AND (reportHolder OR principal:User OR principal:Computer){domain_cond}
              AND (NOT principal:Computer OR coalesce(principal.enabled, true) = true)

            WITH principal, holder, sccmServer, sccmDb, site, p, rels, controlRel, reportHolder, memberPath,
                 CASE
                     WHEN reportHolder THEN ['MSSQL_HasLogin'] + [rel IN rels | type(rel)] + [type(controlRel)]
                     WHEN holder:Group AND memberPath IS NOT NULL
                         THEN [rel IN relationships(memberPath) | type(rel)] + ['MSSQL_HasLogin'] + [rel IN rels | type(rel)] + [type(controlRel)]
                     ELSE [rel IN rels | type(rel)] + [type(controlRel)]
                 END AS pathEdges,
                 CASE
                     WHEN reportHolder THEN [split(coalesce(holder.name, ''), '@')[0]] + {self._path_node_names_expr('nodes(p) + [sccmServer]')}
                     WHEN holder:Group AND memberPath IS NOT NULL
                         THEN {self._path_node_names_expr('nodes(memberPath)')} + {self._path_node_names_expr('nodes(p) + [sccmServer]')}
                     ELSE {self._path_node_names_expr('nodes(p) + [sccmServer]')}
                 END AS pathNodeNames

            RETURN DISTINCT
                   CASE WHEN reportHolder THEN holder.objectid ELSE principal.objectid END AS principalSid,
                   CASE WHEN reportHolder THEN holder.name ELSE principal.name END AS principalName,
                   CASE
                     WHEN reportHolder THEN 'Group'
                     WHEN principal:Computer THEN 'Computer'
                     ELSE 'User'
                   END AS principalType,
                   sccmServer.name AS targetName,
                   'MSSQL_Server' AS targetType,
                   sccmDb.name AS databaseName,
                   sccmServer.name AS serverName,
                   pathEdges,
                   CASE
                     WHEN reportHolder THEN length(p) + 2
                     WHEN holder:Group AND memberPath IS NOT NULL THEN length(memberPath) + length(p) + 2
                     ELSE length(p) + 1
                   END AS pathLength,
                   pathNodeNames,
                   sccmDb.name AS sccmImpactDb,
                   site.siteCode AS sccmImpactSite
        """, parameters={
            "_sccm_path_edges": _SCCM_PATH_EDGES,
            "_server_control_edges": _SERVER_CONTROL_EDGES,
            **sql_login_holder_parameters(),
        }, name="sccm_server_control_paths")
        return self._path_rows(rows)

    def _fetch_linked_sccm_paths(self):
        domain_cond = self._domain_condition("principal")
        holder_domain_cond = self._domain_condition("holder")
        candidate_domain_cond = self._domain_condition("candidatePrincipal")
        member_domain_cond = self._domain_condition("memberPrincipal")
        site_cond = self._site_domain_condition("site")

        rows = self.query(f"""
            MATCH (holder)-[:MSSQL_HasLogin]->(startLogin:MSSQL_Login)
            WHERE holder:User OR holder:Computer OR holder:Group

            WITH holder, startLogin,
                 {sql_login_report_holder_expr()} AS reportHolder
            {sql_login_report_holder_filter(holder_domain_cond, candidate_domain_cond)}
            MATCH (startLogin)-[:MSSQL_Connect]->(srvA:MSSQL_Server)
            MATCH (srvA)-[:MSSQL_LinkedAsAdmin]->(srvB_stub:MSSQL_Server)

            MATCH (srvB:MSSQL_Server)
            WHERE {linked_server_target_resolution('srvB', 'srvB_stub')}
            MATCH (sccmDb:MSSQL_Database)-[:SCCM_AssignAllPermissions]->(site:SCCM_Site)
            WHERE sccmDb.SQLServer = srvB.name{site_cond}

            MATCH (target)
            WHERE
              (target:MSSQL_ServerRole
                  AND toUpper(target.name) IN $_high_value_server_roles
                  AND EXISTS {{ MATCH (srvB)-[:MSSQL_Contains]->(target) }})
              OR (target:MSSQL_DatabaseRole
                  AND toLower(split(target.name, '@')[0]) IN $_high_value_db_roles
                  AND EXISTS {{ MATCH (sccmDb)-[:MSSQL_Contains]->(target) }})
            OPTIONAL MATCH memberPath = (memberPrincipal)-[:MemberOf*1..6]->(holder)
            WHERE holder:Group AND NOT reportHolder
              AND (memberPrincipal:User OR memberPrincipal:Computer){member_domain_cond}
            WITH CASE
                     WHEN reportHolder OR holder:User OR holder:Computer THEN holder
                     ELSE memberPrincipal
                 END AS principal,
                 holder, startLogin, reportHolder, srvA, srvB, sccmDb, site, target, memberPath
            WHERE principal IS NOT NULL
              AND (reportHolder OR principal:User OR principal:Computer){domain_cond}
              AND (NOT principal:Computer OR coalesce(principal.enabled, true) = true)

            RETURN DISTINCT
                   CASE WHEN reportHolder THEN holder.objectid ELSE principal.objectid END AS principalSid,
                   CASE WHEN reportHolder THEN holder.name ELSE principal.name END AS principalName,
                   CASE
                     WHEN reportHolder THEN 'Group'
                     WHEN principal:Computer THEN 'Computer'
                     ELSE 'User'
                   END AS principalType,
                   target.name AS targetName,
                   CASE
                     WHEN target:MSSQL_ServerRole THEN 'MSSQL_ServerRole'
                     WHEN target:MSSQL_DatabaseRole THEN 'MSSQL_DatabaseRole'
                     ELSE 'MSSQL'
                   END AS targetType,
                   CASE WHEN target:MSSQL_DatabaseRole THEN sccmDb.name ELSE null END AS databaseName,
                   srvB.name AS serverName,
                   CASE
                     WHEN reportHolder THEN ['MSSQL_HasLogin', 'MSSQL_Connect', 'MSSQL_LinkedAsAdmin']
                     WHEN holder:Group AND memberPath IS NOT NULL
                         THEN [rel IN relationships(memberPath) | type(rel)] + ['MSSQL_HasLogin', 'MSSQL_Connect', 'MSSQL_LinkedAsAdmin']
                     ELSE ['MSSQL_Connect', 'MSSQL_LinkedAsAdmin']
                   END AS pathEdges,
                   CASE
                     WHEN reportHolder THEN 3
                     WHEN holder:Group AND memberPath IS NOT NULL THEN length(memberPath) + 3
                     ELSE 2
                   END AS pathLength,
                   CASE
                     WHEN reportHolder THEN [split(coalesce(holder.name, ''), '@')[0], startLogin.name, srvA.name, srvB.name]
                     WHEN holder:Group AND memberPath IS NOT NULL
                         THEN {self._path_node_names_expr('nodes(memberPath)')} + [startLogin.name, srvA.name, srvB.name]
                     ELSE [startLogin.name, srvA.name, srvB.name]
                   END AS pathNodeNames,
                   sccmDb.name AS sccmImpactDb,
                   site.siteCode AS sccmImpactSite
        """, parameters={
            "_high_value_server_roles": _HIGH_VALUE_SERVER_ROLES,
            "_high_value_db_roles": _HIGH_VALUE_DB_ROLES,
            **sql_login_holder_parameters(),
        }, name="sccm_linked_server_paths")
        return self._path_rows(rows)

    def _fetch_linked_execute_host_sccm_paths(self):
        domain_cond = self._domain_condition("principal")
        holder_domain_cond = self._domain_condition("holder")
        candidate_domain_cond = self._domain_condition("candidatePrincipal")
        member_domain_cond = self._domain_condition("memberPrincipal")
        site_cond = self._site_domain_condition("site")

        rows = self.query(f"""
            MATCH (holder)-[:MSSQL_HasLogin]->(startLogin:MSSQL_Login)
            WHERE holder:User OR holder:Computer OR holder:Group

            WITH holder, startLogin,
                 {sql_login_report_holder_expr()} AS reportHolder
            {sql_login_report_holder_filter(holder_domain_cond, candidate_domain_cond)}

            MATCH pre = (startLogin)-[preR*1..5]->(src:MSSQL_Server)
            WHERE ALL(rel IN preR WHERE type(rel) IN $_linked_pre_edges)
              AND type(last(preR)) IN $_server_reach_edges
              AND all(node IN nodes(pre) WHERE single(seen IN nodes(pre) WHERE seen = node))

            MATCH (src)-[link:MSSQL_LinkedAsAdmin|MSSQL_LinkedTo]->(linkedStub:MSSQL_Server)
            MATCH (linked:MSSQL_Server)
            WHERE linked = linkedStub
               OR {linked_server_target_resolution('linked', 'linkedStub')}
            WITH holder, startLogin, reportHolder, pre, preR, src, link, linked
            WHERE (
                type(link) = 'MSSQL_LinkedAsAdmin'
                OR coalesce(link.remoteIsSysadmin, false) = true
                OR coalesce(link.remoteIsSecurityAdmin, false) = true
                OR coalesce(link.remoteHasControlServer, false) = true
                OR coalesce(link.remoteHasImpersonateAnyLogin, false) = true
              )
              AND coalesce(link.rpcOut, true) = true

            MATCH post = (linked)-[:MSSQL_ExecuteOnHost]->(host:Computer)
                         -[:SCCM_AssignAllPermissions]->(site:SCCM_Site)
            WHERE coalesce(host.enabled, true) = true
              AND true{site_cond}

            WITH holder, startLogin, reportHolder, pre, preR, src, link, linked, post, host, site,
                 CASE
                   WHEN any(rel IN preR WHERE type(rel) IN $_assume_role_edges) THEN 0
                   ELSE 1
                 END AS assumeRank,
                 CASE WHEN type(link) = 'MSSQL_LinkedAsAdmin' THEN 0 ELSE 1 END AS linkRank,
                 CASE
                   WHEN any(rel IN preR WHERE type(rel) = 'MSSQL_ExecuteAs') THEN 0
                   ELSE 1
                 END AS executeAsRank
            ORDER BY assumeRank, length(pre), linkRank, executeAsRank
            WITH holder, startLogin, reportHolder, src, linked, host, site,
                 collect({{pre: pre, link: link, post: post}})[0] AS selected
            WITH holder, startLogin, reportHolder, src, linked, host, site,
                 selected.pre AS pre,
                 selected.link AS link,
                 selected.post AS post

            OPTIONAL MATCH (serviceAccount)-[:MSSQL_ServiceAccountFor]->(linked)
            WITH holder, startLogin, reportHolder, src, linked, host, site, pre, link, post,
                 coalesce(serviceAccount.name, serviceAccount.objectid) AS serviceAccountName
            ORDER BY serviceAccountName
            WITH holder, startLogin, reportHolder, src, linked, host, site, pre, link, post,
                 [name IN collect(DISTINCT serviceAccountName) WHERE name IS NOT NULL] AS serviceAccountNames

            OPTIONAL MATCH memberPath = (memberPrincipal)-[:MemberOf*1..6]->(holder)
            WHERE holder:Group AND NOT reportHolder
              AND (memberPrincipal:User OR memberPrincipal:Computer){member_domain_cond}
            WITH CASE
                     WHEN reportHolder OR holder:User OR holder:Computer THEN holder
                     ELSE memberPrincipal
                 END AS principal,
                 holder, pre, link, linked, post, host, site, serviceAccountNames,
                 reportHolder, memberPath
            WHERE principal IS NOT NULL
              AND (reportHolder OR principal:User OR principal:Computer){domain_cond}
              AND (NOT principal:Computer OR coalesce(principal.enabled, true) = true)

            WITH principal, holder, link, linked, pre, post, host, site,
                 CASE
                   WHEN size(serviceAccountNames) > 0 THEN
                     'as ' + reduce(
                       text = '',
                       name IN serviceAccountNames |
                       text + CASE WHEN text = '' THEN '' ELSE ', ' END + name
                     )
                   ELSE null
                 END AS executeOnHostContext,
                 reportHolder, memberPath

            WITH principal, holder, link, linked, pre, post, host, site,
                 executeOnHostContext, reportHolder, memberPath,
                 [rel IN relationships(pre) | type(rel)] + [type(link)] +
                     [rel IN relationships(post) | type(rel)] AS coreEdges,
                 [rel IN relationships(pre) | null] + [null] +
                     [rel IN relationships(post) |
                        CASE
                          WHEN type(rel) = 'MSSQL_ExecuteOnHost' THEN executeOnHostContext
                          ELSE null
                        END] AS coreEdgeContexts,
                 {self._path_node_names_expr('nodes(pre)')} +
                     [coalesce(linked.name, linked.objectid, 'Unknown')] +
                     {self._path_node_names_expr('tail(nodes(post))')} AS coreNodes

            RETURN DISTINCT
                   CASE WHEN reportHolder THEN holder.objectid ELSE principal.objectid END AS principalSid,
                   CASE WHEN reportHolder THEN holder.name ELSE principal.name END AS principalName,
                   CASE
                     WHEN reportHolder THEN 'Group'
                     WHEN principal:Computer THEN 'Computer'
                     ELSE 'User'
                   END AS principalType,
                   site.siteCode AS targetName,
                   'SCCM_Site' AS targetType,
                   null AS databaseName,
                   linked.name AS serverName,
                   CASE
                     WHEN holder:Group AND memberPath IS NOT NULL
                         THEN [rel IN relationships(memberPath) | type(rel)] + ['MSSQL_HasLogin'] + coreEdges
                     ELSE ['MSSQL_HasLogin'] + coreEdges
                   END AS pathEdges,
                   CASE
                     WHEN holder:Group AND memberPath IS NOT NULL
                         THEN [rel IN relationships(memberPath) | null] + [null] + coreEdgeContexts
                     ELSE [null] + coreEdgeContexts
                   END AS pathEdgeContexts,
                   CASE
                     WHEN holder:Group AND memberPath IS NOT NULL THEN length(memberPath) + size(coreEdges) + 1
                     ELSE size(coreEdges) + 1
                   END AS pathLength,
                   CASE
                     WHEN holder:Group AND memberPath IS NOT NULL
                         THEN {self._path_node_names_expr('nodes(memberPath)')} + coreNodes
                     ELSE [split(coalesce(holder.name, ''), '@')[0]] + coreNodes
                   END AS pathNodeNames,
                   null AS sccmImpactDb,
                   site.siteCode AS sccmImpactSite
        """, parameters={
            "_linked_pre_edges": _LINKED_PRE_EDGES,
            "_server_reach_edges": _SERVER_REACH_EDGES,
            "_assume_role_edges": _ASSUME_ROLE_EDGES,
            **sql_login_holder_parameters(),
        }, name="sccm_linked_execute_host_paths")
        return self._path_rows(rows)

    def _fetch_coercion_paths(self):
        source_domain_cond = self._domain_condition("source")
        site_cond = self._site_domain_condition("site")

        rows = self.query(f"""
            MATCH (source)-[relay]->(login:MSSQL_Login)
            WHERE type(relay) IN ['CoerceAndRelayToMSSQL', 'MSSQL_CoerceAndRelayToMSSQL']
              AND (
                ((source:User OR source:Computer OR source:Group){source_domain_cond})
                OR NOT (source:User OR source:Computer OR source:Group)
              )
              AND (NOT source:Computer OR coalesce(source.enabled, true) = true)

            WITH source, relay, login, toLower(split(login.SQLServer, ':')[0]) AS loginHost
            MATCH (sccmDb:MSSQL_Database)-[:SCCM_AssignAllPermissions]->(site:SCCM_Site)
            WHERE toLower(split(sccmDb.SQLServer, ':')[0]) = loginHost{site_cond}

            RETURN DISTINCT
                   CASE
                       WHEN source:Group THEN 'Group'
                       WHEN source:Computer THEN 'Computer'
                       WHEN source:User THEN 'User'
                       WHEN source:MSSQL_Base THEN 'MSSQL'
                       WHEN source:SCCM_Base THEN 'SCCM'
                       ELSE coalesce({primary_label_expr('source')}, 'Unknown')
                   END AS sourceType,
                   coalesce(source.name, source.objectid) AS sourceName,
                   source.objectid AS sourceSid,
                   login.name AS loginName,
                   login.SQLServer AS sqlServer,
                   sccmDb.name AS sccmImpactDb,
                   site.siteCode AS sccmImpactSite,
                   type(relay) AS relayType
        """, name="sccm_coercion_paths")

        paths = []
        for row in rows:
            paths.append({
                'attack_type': 'coercion',
                'principal_sid': row.get('sourceSid'),
                'principal_name': row.get('sourceName') or '',
                'principal_type': row.get('sourceType') or '',
                'target_name': row.get('loginName') or '',
                'target_type': 'MSSQL_Login',
                'database_name': row.get('sccmImpactDb') or '',
                'server_name': row.get('sqlServer') or '',
                'path_edges': [row.get('relayType') or 'CoerceAndRelayToMSSQL'],
                'path_length': 1,
                'sccm_impact_db': row.get('sccmImpactDb') or '',
                'sccm_impact_site': row.get('sccmImpactSite') or '',
            })

        return self._prefer_ad_coercion_sources(paths)

    def _fetch_service_account_paths(self):
        site_cond = self._site_domain_condition("site")
        service_account_domain_cond = self._domain_condition("serviceAccount")

        rows = self.query(f"""
            MATCH (sccmDb:MSSQL_Database)-[:SCCM_AssignAllPermissions]->(site:SCCM_Site)
            WHERE true{site_cond}

            WITH DISTINCT sccmDb.SQLServer AS sqlServer,
                 collect(DISTINCT sccmDb.name) AS sccmDatabases,
                 collect(DISTINCT site.siteCode) AS sccmSites

            MATCH (serviceAccount)-[:MSSQL_ServiceAccountFor]->(:MSSQL_Server {{name: sqlServer}})
            WHERE (
                ((serviceAccount:User OR serviceAccount:Computer OR serviceAccount:Group){service_account_domain_cond})
                OR NOT (serviceAccount:User OR serviceAccount:Computer OR serviceAccount:Group)
              )
              AND (NOT serviceAccount:Computer OR coalesce(serviceAccount.enabled, true) = true)

            RETURN DISTINCT
                   CASE
                       WHEN serviceAccount:Group THEN 'Group'
                       WHEN serviceAccount:Computer THEN 'Computer'
                       WHEN serviceAccount:User THEN 'User'
                       WHEN serviceAccount:MSSQL_Base THEN 'MSSQL'
                       WHEN serviceAccount:SCCM_Base THEN 'SCCM'
                       ELSE coalesce({primary_label_expr('serviceAccount')}, 'Unknown')
                   END AS serviceAccountType,
                   serviceAccount.name AS serviceAccountName,
                   serviceAccount.objectid AS serviceAccountSid,
                   sqlServer,
                   sccmDatabases,
                   sccmSites
        """, name="sccm_service_account_paths")

        paths = []
        for row in rows:
            databases = row.get('sccmDatabases') or []
            sites = row.get('sccmSites') or []
            paths.append({
                'attack_type': 'service_account',
                'principal_sid': row.get('serviceAccountSid'),
                'principal_name': row.get('serviceAccountName') or '',
                'principal_type': row.get('serviceAccountType') or '',
                'target_name': 'SQL Server Service Account',
                'target_type': 'MSSQL_Server',
                'database_name': ', '.join(databases),
                'server_name': row.get('sqlServer') or '',
                'path_edges': ['MSSQL_ServiceAccountFor'],
                'path_length': 1,
                'sccm_impact_db': databases[0] if databases else '',
                'sccm_impact_site': sites[0] if sites else '',
            })
        return paths

    def _path_rows(self, rows):
        paths = []
        for row in rows:
            paths.append({
                'attack_type': 'privilege_escalation',
                'principal_sid': row.get('principalSid'),
                'principal_name': row.get('principalName') or '',
                'principal_type': row.get('principalType') or '',
                'target_name': row.get('targetName') or '',
                'target_type': row.get('targetType') or '',
                'database_name': row.get('databaseName') or '',
                'server_name': row.get('serverName') or '',
                'path_edges': row.get('pathEdges') or [],
                'path_edge_contexts': row.get('pathEdgeContexts') or [],
                'path_length': row.get('pathLength') or 0,
                'path_node_names': row.get('pathNodeNames') or [],
                'sccm_impact_db': row.get('sccmImpactDb') or '',
                'sccm_impact_site': row.get('sccmImpactSite') or '',
            })
        return paths

    def _prefer_ad_coercion_sources(self, paths):
        grouped = {}
        for path in paths:
            key = (
                self._normalize_host(path.get('server_name') or ''),
                path.get('sccm_impact_site') or '',
            )
            grouped.setdefault(key, []).append(path)

        kept = []
        for group in grouped.values():
            ad_paths = [
                path for path in group
                if path.get('principal_type') in ('User', 'Computer', 'Group')
            ]
            if not ad_paths:
                kept.extend(group)
                continue

            ad_names = {
                self._clean_name(path.get('principal_name') or '').lower()
                for path in ad_paths
            }
            kept.extend(
                path for path in group
                if path.get('principal_type') in ('User', 'Computer', 'Group')
                or self._clean_name(path.get('principal_name') or '').lower() not in ad_names
            )
        return kept

    def _format_principal(self, paths):
        seen = set()
        deduped = []

        for path in paths:
            dedup = (
                path.get('attack_type', ''),
                path.get('target_name', ''),
                path.get('server_name', ''),
                tuple(path.get('path_edges', [])),
                path.get('sccm_impact_site', ''),
            )
            if dedup in seen:
                continue
            seen.add(dedup)
            deduped.append(path)

        deduped = self._suppress_subordinate_sql_roles(deduped)
        deduped.sort(key=lambda path: (
            0 if path.get('attack_type') == 'privilege_escalation' else
            1 if path.get('attack_type') == 'coercion' else 2,
            path.get('path_length', 0),
        ))

        lines = []
        for path in deduped:
            line = self._format_path_line(path)
            if line:
                lines.append(line)
        return lines

    def _suppress_subordinate_sql_roles(self, paths):
        role_names_by_scope = {}
        for path in paths:
            if path.get('target_type') not in ('MSSQL_ServerRole', 'MSSQL_DatabaseRole'):
                continue
            key = (
                path.get('target_type'),
                path.get('server_name') or '',
                path.get('database_name') or '',
                path.get('sccm_impact_site') or '',
            )
            role_names_by_scope.setdefault(key, set()).add(
                self._role_key(path.get('target_name') or '')
            )

        filtered = []
        for path in paths:
            target_type = path.get('target_type')
            target_name = self._role_key(path.get('target_name') or '')
            key = (
                target_type,
                path.get('server_name') or '',
                path.get('database_name') or '',
                path.get('sccm_impact_site') or '',
            )
            scope_roles = role_names_by_scope.get(key, set())
            if target_type == 'MSSQL_ServerRole' and 'SYSADMIN' in scope_roles:
                if target_name in _SYSADMIN_SUBORDINATES:
                    continue
            if target_type == 'MSSQL_DatabaseRole' and 'DB_OWNER' in scope_roles:
                if target_name in _DB_OWNER_SUBORDINATES:
                    continue
            filtered.append(path)
        return filtered

    def _role_key(self, name):
        return (name or '').split('@')[0].upper()

    def _format_path_line(self, path):
        attack_type = path.get('attack_type', '')
        server = (path.get('server_name') or '').split(':')[0]
        server_display = server.lower() if server else 'unknown'

        if attack_type == 'privilege_escalation':
            chain = self._build_chain(path)
            return self._append_sccm_scope(chain, path)

        if attack_type == 'coercion':
            target_login = self._clean_name(path.get('target_name', '') or 'unknown login')
            principal_name = self._clean_name(path.get('principal_name', '') or 'principal')
            edge = (path.get('path_edges') or ['CoerceAndRelayToMSSQL'])[0]
            return self._append_sccm_scope(
                f"{principal_name} -> {edge} -> {target_login}",
                path,
            )

        if attack_type == 'service_account':
            principal_name = self._clean_name(path.get('principal_name', '') or 'principal')
            return self._append_sccm_scope(
                f"{principal_name} -> MSSQL_ServiceAccountFor -> {server_display}",
                path,
            )

        return ""

    def _build_chain(self, path):
        edges = path.get('path_edges', [])
        edge_contexts = path.get('path_edge_contexts', [])
        nodes = path.get('path_node_names', [])

        if not edges or not nodes:
            return ""

        parts = [self._clean_name(nodes[0])]
        for i, edge in enumerate(edges):
            next_name = self._clean_name(nodes[i + 1]) if i + 1 < len(nodes) else "?"
            context = edge_contexts[i] if i < len(edge_contexts) else None
            parts.append(self._format_edge(edge, context))
            parts.append(next_name)

        raw_target = path.get('target_name') or ''
        target_name = self._clean_name(raw_target) if raw_target else ''
        if target_name and target_name not in parts[-1]:
            parts[-1] = f"{parts[-1]} ({target_name})"

        return " -> ".join(parts)

    def _format_edge(self, edge, context=None):
        if context:
            return f"{edge} ({context})"
        return edge

    def _append_sccm_scope(self, chain, path):
        scope = self._sccm_scope_chain(path)
        if chain and scope:
            return f"{chain} | {scope}"
        return chain or scope

    def _sccm_scope_chain(self, path):
        target_type = path.get('target_type', '')
        if target_type in ('SCCM_Site', 'SCCM_AdminUser'):
            return ''

        site = path.get('sccm_impact_site') or ''
        if not site:
            return ''

        db = path.get('sccm_impact_db') or ''
        if db:
            return f"MSSQL_Database({db}) -> SCCM_AssignAllPermissions -> SCCM_Site({site})"
        return f"SCCM_AssignAllPermissions -> SCCM_Site({site})"

    def _path_node_names_expr(self, nodes_expr):
        return f"""[node IN {nodes_expr} | CASE
                       WHEN node:MSSQL_Database
                           THEN 'MSSQL_Database(' + coalesce(node.name, node.objectid, 'Unknown') + ')'
                       WHEN node:SCCM_Site
                           THEN 'SCCM_Site(' + coalesce(node.siteCode, node.displayName, node.objectid, 'Unknown') + ')'
                       ELSE coalesce(
                           node.name,
                           node.siteCode,
                           node.displayName,
                           {primary_label_expr('node')},
                           'Unknown'
                       )
                   END]"""

    def _normalize_host(self, name):
        return (name or '').split(':')[0].lower()

    def _clean_name(self, name):
        if not name:
            return "?"
        if '\\' in name:
            name = name.split('\\')[-1]
        if '@' in name:
            base, suffix = name.rsplit('@', 1)
            if '.' in suffix:
                name = base
        if ':' in name:
            name = name.split(':')[0]
        return name
