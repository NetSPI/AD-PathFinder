// Linked-server pivot where the OpenGraph stub is SID-named. The bridge must
// fall back to matching the SID prefix because stub.name does not contain
// srvA.sqlServerName.

CREATE (srvA:MSSQL_Server {
  name: 'lab-sql01.test.local:1433',
  sqlServerName: 'lab-sql01\\SQL01',
  objectid: 'S-1-5-21-TEST-4806:1433'
});

CREATE (stub:MSSQL_Base {
  name: 'S-1-5-21-TEST-4806:SQL01',
  objectid: 'S-1-5-21-TEST-4806:SQL01'
});

CREATE (srvBStub:MSSQL_Server {
  name: 'sccmdb.test.local'
});

CREATE (srvB:MSSQL_Server {
  name: 'sccmdb.test.local:1433'
});

CREATE (role:MSSQL_ServerRole {
  name: 'sysadmin',
  SQLServer: 'sccmdb.test.local:1433'
});

CREATE (u:User {
  name: 'SIDLINK@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-3301',
  enabled: true,
  domain: 'TEST.LOCAL'
});

CREATE (login:MSSQL_Login {
  name: 'TEST\\sidlink',
  SQLServer: 'lab-sql01.test.local:1433'
});

MATCH (u:User {objectid: 'S-1-5-21-TEST-3301'}),
      (login:MSSQL_Login {name: 'TEST\\sidlink'}),
      (srvA:MSSQL_Server {name: 'lab-sql01.test.local:1433'}),
      (srvB:MSSQL_Server {name: 'sccmdb.test.local:1433'}),
      (srvBStub:MSSQL_Server {name: 'sccmdb.test.local'}),
      (stub:MSSQL_Base {name: 'S-1-5-21-TEST-4806:SQL01'}),
      (role:MSSQL_ServerRole {name: 'sysadmin'})
CREATE (u)-[:MSSQL_HasLogin]->(login)
CREATE (login)-[:MSSQL_Connect]->(srvA)
CREATE (stub)-[:MSSQL_LinkedAsAdmin]->(srvBStub)
CREATE (srvB)-[:MSSQL_Contains]->(role);
