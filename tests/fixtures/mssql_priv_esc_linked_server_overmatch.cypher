// SQL01-BAK must not bridge through a substring match on SQL01.

CREATE (srvA:MSSQL_Server {
  name: 'lab-sql01.test.local:1433',
  sqlServerName: 'lab-sql01\\SQL01',
  objectid: 'S-1-5-21-TEST-4806:1433'
});

CREATE (stub:MSSQL_Base {
  name: 'LinkedServer:LAB-SQL01\\SQL01-BAK'
});

CREATE (srvB:MSSQL_Server {
  name: 'sccmdb.test.local:1433'
});

CREATE (role:MSSQL_ServerRole {
  name: 'sysadmin',
  SQLServer: 'sccmdb.test.local:1433'
});

CREATE (u:User {
  name: 'OVERMATCH@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-3501',
  enabled: true,
  domain: 'TEST.LOCAL'
});

CREATE (login:MSSQL_Login {
  name: 'TEST\\overmatch',
  SQLServer: 'lab-sql01.test.local:1433'
});

MATCH (u:User {objectid: 'S-1-5-21-TEST-3501'}),
      (login:MSSQL_Login {name: 'TEST\\overmatch'}),
      (srvA:MSSQL_Server {name: 'lab-sql01.test.local:1433'}),
      (srvB:MSSQL_Server {name: 'sccmdb.test.local:1433'}),
      (stub:MSSQL_Base {name: 'LinkedServer:LAB-SQL01\\SQL01-BAK'}),
      (role:MSSQL_ServerRole {name: 'sysadmin'})
CREATE (u)-[:MSSQL_HasLogin]->(login)
CREATE (login)-[:MSSQL_Connect]->(srvA)
CREATE (stub)-[:MSSQL_LinkedAsAdmin]->(srvB)
CREATE (srvB)-[:MSSQL_Contains]->(role);
