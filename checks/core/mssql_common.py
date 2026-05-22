COMMON_SQL_LOGIN_HOLDER_NAMES = [
    'DOMAIN USERS', 'DOMAIN COMPUTERS', 'AUTHENTICATED USERS',
    'EVERYONE', 'BUILTIN\\USERS', 'USERS',
]

COMMON_SQL_LOGIN_HOLDER_SIDS = [
    'S-1-1-0', 'S-1-5-11', 'S-1-5-32-545',
]

MSSQL_ABUSE_EDGES = [
    'MSSQL_HasLogin', 'MSSQL_Connect', 'MSSQL_IsMappedTo', 'MSSQL_MemberOf',
    'MSSQL_AddMember', 'MSSQL_ControlServer', 'MSSQL_ControlDB', 'MSSQL_Control',
    'MSSQL_AlterAnyLogin', 'MSSQL_AlterAnyDBRole', 'MSSQL_AlterAnyAppRole',
    'MSSQL_AlterAnyServerRole', 'MSSQL_GrantAnyPermission', 'MSSQL_GrantAnyDBPermission',
    'MSSQL_Impersonate', 'MSSQL_ImpersonateAnyLogin', 'MSSQL_ExecuteAs',
    'MSSQL_ExecuteAsOwner', 'MSSQL_TakeOwnership', 'MSSQL_ChangeOwner',
    'MSSQL_ChangePassword', 'MSSQL_LinkedAsAdmin', 'MSSQL_Owns',
    'MSSQL_HasMappedCred', 'MSSQL_HasProxyCred', 'MSSQL_HasDBScopedCred',
]


def sql_login_holder_parameters():
    return {
        "_common_sql_login_holder_names": COMMON_SQL_LOGIN_HOLDER_NAMES,
        "_common_sql_login_holder_sids": COMMON_SQL_LOGIN_HOLDER_SIDS,
    }


def sql_login_report_holder_expr(holder_var="holder"):
    return f"""{holder_var}:Group AND (
                     toUpper(split(coalesce({holder_var}.name, ''), '@')[0]) IN $_common_sql_login_holder_names
                     OR coalesce({holder_var}.objectid, '') IN $_common_sql_login_holder_sids
                     OR coalesce({holder_var}.objectid, '') ENDS WITH '-513'
                     OR coalesce({holder_var}.objectid, '') ENDS WITH '-515'
                 )"""


def sql_login_report_holder_filter(
    holder_domain_cond,
    candidate_domain_cond,
    holder_var="holder",
    candidate_var="candidatePrincipal",
):
    # Expects sql_login_report_holder_expr() to be aliased as reportHolder.
    return f"""WHERE ((reportHolder OR {holder_var}:User OR {holder_var}:Computer){holder_domain_cond})
               OR ({holder_var}:Group AND NOT reportHolder AND EXISTS {{
                    MATCH ({candidate_var})-[:MemberOf*1..6]->({holder_var})
                    WHERE ({candidate_var}:User OR {candidate_var}:Computer){candidate_domain_cond}
               }})"""


def primary_label_expr(var):
    return (
        f"head([label IN labels({var}) "
        f"WHERE NOT label IN ['Base', 'MSSQL_Base', 'SCCM_Base', "
        f"'OpenGraph_Stub', 'ADLocalGroup', 'LocalGroup'] "
        f"AND NOT label STARTS WITH 'Tag_'])"
    )
