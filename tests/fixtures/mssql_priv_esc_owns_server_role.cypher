// Login ownership of a high-value server role is an escalation path:
// owning sysadmin lets you add yourself to it.

CREATE (srv:MSSQL_Server {
  name: 'sql01.test.local:1433',
  sqlServerName: 'sql01',
  objectid: 'S-1-5-21-TEST-4001:1433'
});

CREATE (role:MSSQL_ServerRole {
  name: 'sysadmin',
  SQLServer: 'sql01.test.local:1433'
});

CREATE (u:User {
  name: 'OWNSROLE@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-3601',
  enabled: true,
  domain: 'TEST.LOCAL'
});

CREATE (login:MSSQL_Login {
  name: 'TEST\\ownsrole',
  SQLServer: 'sql01.test.local:1433'
});

MATCH (u:User {objectid: 'S-1-5-21-TEST-3601'}),
      (login:MSSQL_Login {name: 'TEST\\ownsrole'}),
      (srv:MSSQL_Server {name: 'sql01.test.local:1433'}),
      (role:MSSQL_ServerRole {name: 'sysadmin'})
CREATE (u)-[:MSSQL_HasLogin]->(login)
CREATE (login)-[:MSSQL_Connect]->(srv)
CREATE (login)-[:MSSQL_Owns]->(role)
CREATE (srv)-[:MSSQL_Contains]->(role);
