from .opengraph_identifiers import safe_cypher_identifier


def _merge_mssql_server_node(connection, stale: str, canonical: str) -> None:
    counts = connection.query(
        "MATCH (n:MSSQL_Server) WHERE n.objectid IN [$stale, $canonical] "
        "RETURN n.objectid AS oid, count(*) AS c",
        parameters={'stale': stale, 'canonical': canonical},
    )
    if any(row['c'] > 1 for row in counts or []):
        print(
            f"[!] Skipped MSSQL_Server merge — duplicate objectid "
            f"(stale={stale!r}, canonical={canonical!r})"
        )
        return
    connection.query(
        "MATCH (s:MSSQL_Server {objectid: $stale}) "
        "MATCH (c:MSSQL_Server {objectid: $canonical}) "
        "WITH c, properties(s) AS sp, properties(c) AS cp "
        "SET c += sp SET c += cp",
        parameters={'stale': stale, 'canonical': canonical},
    )
    rel_types = connection.query(
        "MATCH (s:MSSQL_Server {objectid: $stale})-[r]-() "
        "RETURN DISTINCT type(r) AS rtype",
        parameters={'stale': stale},
    )
    for rt in rel_types:
        rtype = safe_cypher_identifier(rt['rtype'], 'relationship type')
        connection.query(
            f"MATCH (s:MSSQL_Server {{objectid: $stale}})-[old:`{rtype}`]->(t) "
            f"MATCH (c:MSSQL_Server {{objectid: $canonical}}) "
            "WHERE t <> c "
            f"MERGE (c)-[new:`{rtype}`]->(t) "
            "WITH old, new, properties(old) AS old_props, properties(new) AS existing_props "
            "SET new += old_props SET new += existing_props "
            "DELETE old",
            parameters={'stale': stale, 'canonical': canonical},
        )
        connection.query(
            f"MATCH (src)-[old:`{rtype}`]->(s:MSSQL_Server {{objectid: $stale}}) "
            f"MATCH (c:MSSQL_Server {{objectid: $canonical}}) "
            "WHERE src <> c "
            f"MERGE (src)-[new:`{rtype}`]->(c) "
            "WITH old, new, properties(old) AS old_props, properties(new) AS existing_props "
            "SET new += old_props SET new += existing_props "
            "DELETE old",
            parameters={'stale': stale, 'canonical': canonical},
        )
    connection.query(
        "MATCH (s:MSSQL_Server {objectid: $stale}) DETACH DELETE s",
        parameters={'stale': stale},
    )


def dedupe_mssql_servers(connection) -> int:
    groups = connection.query("""
        MATCH (s:MSSQL_Server)
        WHERE s.name IS NOT NULL
        WITH s, toLower(s.name) AS canon
        WITH canon, collect(s) AS servers
        WHERE size(servers) > 1
        UNWIND servers AS s
        OPTIONAL MATCH (s)-[r]-()
        WITH canon, s, count(r) AS deg, size(keys(s)) AS prop_count
        ORDER BY canon, prop_count DESC, deg DESC
        WITH canon, collect(s.objectid) AS ranked
        RETURN head(ranked) AS canonical, tail(ranked) AS stale
    """)

    merged = 0
    for row in groups or []:
        canonical = row['canonical']
        for stale in row['stale']:
            _merge_mssql_server_node(connection, stale, canonical)
            merged += 1

    if merged:
        print(f"[*] Merged {merged} duplicate MSSQL_Server node(s)")
    return merged


