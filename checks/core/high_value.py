from modules.hv_groups import HIGH_VALUE_GROUPS_UPPER


def name_variants(name):
    if not name:
        return set()
    upper = str(name).upper()
    variants = {upper}
    account_part = upper.split('@')[0]
    variants.add(account_part)
    if '\\' in account_part:
        variants.add(account_part.split('\\')[-1])
    return {variant for variant in variants if variant}


def _add_variants(target, names):
    for name in names or []:
        target.update(name_variants(name))


def high_value_principal_sets(neo4j_data):
    users = set()
    computers = set()
    groups = set(HIGH_VALUE_GROUPS_UPPER)

    admin_users, admin_computers = neo4j_data.get_admin_users_and_computers()
    _add_variants(users, admin_users)
    _add_variants(computers, admin_computers)

    return users, computers, groups


def enrich_high_value_principal_sets(
    users,
    computers,
    groups,
    query,
    domain_condition="",
    query_name="high_value_graph_principals",
):
    for row in query(f"""
        MATCH (p)
        WHERE (p:User OR p:Computer OR p:Group)
          AND p.name IS NOT NULL
          AND (
            p.highvalue = true
            OR p:Tag_Tier_Zero
            OR coalesce(p.system_tags, '') CONTAINS 'admin_tier_0'
          ){domain_condition}
        RETURN DISTINCT p.name AS name,
               CASE
                 WHEN p:User THEN 'User'
                 WHEN p:Computer THEN 'Computer'
                 WHEN p:Group THEN 'Group'
               END AS type
    """, name=query_name) or []:
        target = None
        if row.get('type') == 'User':
            target = users
        elif row.get('type') == 'Computer':
            target = computers
        elif row.get('type') == 'Group':
            target = groups
        if target is not None:
            target.update(name_variants(row.get('name')))


def high_value_principal_sets_for_check(check, query_name="high_value_graph_principals"):
    domain_condition = check._domain_condition("p")
    cache = check.neo4j_data._hv_principal_sets_cache
    lock = check.neo4j_data._hv_principal_sets_lock
    with lock:
        if domain_condition in cache:
            return cache[domain_condition]

        users, computers, groups = high_value_principal_sets(check.neo4j_data)
        enrich_high_value_principal_sets(
            users,
            computers,
            groups,
            check.query,
            domain_condition,
            query_name,
        )

        cache[domain_condition] = (users, computers, groups)
        return users, computers, groups


def is_high_value_principal(name, principal_type, users, computers, groups):
    variants = name_variants(name)
    if not variants:
        return False
    if principal_type == 'User':
        return bool(variants & users)
    if principal_type == 'Computer':
        return bool(variants & computers)
    if principal_type == 'Group':
        return bool(variants & groups)
    return False
