// MSSQL_SCCM hybrid positive: a domain user has an MSSQL_Login that controls
// the SCCM site database, which in turn -[:SCCM_AssignAllPermissions]-> the
// SCCM_Site. Cross-schema path with traversable=true on every edge.

CREATE (site:SCCM_Site {siteCode: 'P01', sourceForest: 'TEST.LOCAL'});

CREATE (server:MSSQL_Server {
  name: 'sql01.test.local:1433',
  xpCmdShellEnabled: false,
  extendedProtection: false
});

CREATE (login:MSSQL_Login {
  name: 'TEST\\sccmadmin',
  SQLServer: 'sql01.test.local:1433',
  type: 'WINDOWS_LOGIN'
});

CREATE (sccmDb:MSSQL_Database {
  name: 'CM_P01',
  SQLServer: 'sql01.test.local:1433',
  isTrustworthy: true
});

CREATE (u:User {
  name: 'sccmadmin@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-1300',
  enabled: true,
  domain: 'TEST.LOCAL'
});

// shortestPath() requires every edge in the chain to carry traversable=true,
// regardless of which schema the edge belongs to (mssql_sccm.py:82).
MATCH (u:User {objectid: 'S-1-5-21-TEST-1300'}),
      (login:MSSQL_Login {name: 'TEST\\sccmadmin'}),
      (sccmDb:MSSQL_Database {name: 'CM_P01'}),
      (site:SCCM_Site {siteCode: 'P01'})
CREATE (u)-[:MSSQL_HasLogin {traversable: true}]->(login)
CREATE (login)-[:MSSQL_ControlDB {traversable: true}]->(sccmDb)
CREATE (sccmDb)-[:SCCM_AssignAllPermissions {traversable: true}]->(site);
