// Positive: non-admin user has a login that reaches sysadmin via a
// two-hop shortestPath chain. All edges carry traversable=true.

CREATE (server:MSSQL_Server {
  name: 'sql01.test.local:1433',
  xpCmdShellEnabled: false
});

CREATE (u:User {
  name: 'LOWPRIV@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-3101',
  enabled: true,
  domain: 'TEST.LOCAL'
});

CREATE (login:MSSQL_Login {
  name: 'TEST\\lowpriv',
  SQLServer: 'sql01.test.local:1433',
  type: 'WINDOWS_LOGIN'
});

CREATE (role:MSSQL_ServerRole {
  name: 'sysadmin',
  SQLServer: 'sql01.test.local:1433'
});

// Principal -> Login -> Role (all traversable)
MATCH (u:User {objectid: 'S-1-5-21-TEST-3101'}),
      (login:MSSQL_Login {name: 'TEST\\lowpriv'}),
      (role:MSSQL_ServerRole {name: 'sysadmin'})
CREATE (u)-[:MSSQL_HasLogin {traversable: true}]->(login)
CREATE (login)-[:MSSQL_MemberOf {traversable: true}]->(role);
