from .opengraph_identifiers import safe_cypher_identifier


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
            merged += 1

    if merged:
        print(f"[*] Merged {merged} duplicate MSSQL_Server node(s)")
    return merged


def canonicalize_mssql_linked_server_edges(connection) -> int:
    created = 0
    for rel_type in ("MSSQL_LinkedTo", "MSSQL_LinkedAsAdmin"):
        rtype = safe_cypher_identifier(rel_type, "relationship type")
        rows = connection.query(f"""
            MATCH (stub:MSSQL_Base)-[old:`{rtype}`]->(target:MSSQL_Server)
            WHERE NOT stub:MSSQL_Server
              AND stub.objectid IS NOT NULL
              AND stub.objectid CONTAINS ':'
            WITH old, target, split(stub.objectid, ':')[0] AS sourceSid
            MATCH (source:MSSQL_Server)
            WHERE source.objectid IS NOT NULL
              AND source.objectid CONTAINS ':'
              AND split(source.objectid, ':')[0] = sourceSid
              AND source <> target
              AND COUNT {{
                MATCH (sidServer:MSSQL_Server)
                WHERE sidServer.objectid CONTAINS ':'
                  AND split(sidServer.objectid, ':')[0] = sourceSid
              }} = 1
            MERGE (source)-[new:`{rtype}`]->(target)
            WITH old, new, properties(old) AS old_props, properties(new) AS existing_props
            SET new += old_props SET new += existing_props
            RETURN count(DISTINCT new) AS created
        """)
        if rows:
            created += rows[0].get("created", 0) or 0

    if created:
        print(f"[*] Canonicalized {created} MSSQL linked-server edge(s)")
    return created
