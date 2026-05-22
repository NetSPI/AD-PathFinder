// Ambiguous host SID prefixes shared by SQL instances must not bridge.

CREATE (srvA1:MSSQL_Server {
  name: 'shared-host.test.local:1433',
  sqlServerName: 'shared-host\\INST1',
  objectid: 'S-1-5-21-TEST-SHARED:1433'
});
CREATE (srvA2:MSSQL_Server {
  name: 'shared-host.test.local:1434',
  sqlServerName: 'shared-host\\INST2',
  objectid: 'S-1-5-21-TEST-SHARED:1434'
});

CREATE (stub:MSSQL_Base {
  name: 'S-1-5-21-TEST-SHARED:INST2',
  objectid: 'S-1-5-21-TEST-SHARED:INST2'
});

CREATE (srvBStub:MSSQL_Server {name: 'sccmdb.test.local'});
CREATE (srvB:MSSQL_Server {name: 'sccmdb.test.local:1433'});
CREATE (role:MSSQL_ServerRole {name: 'sysadmin', SQLServer: 'sccmdb.test.local:1433'});

CREATE (u:User {
  name: 'SHAREDSID@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-3703',
  enabled: true,
  domain: 'TEST.LOCAL'
});

CREATE (login:MSSQL_Login {
  name: 'TEST\\sharedsid',
  SQLServer: 'shared-host.test.local:1433'
});

MATCH (u:User {objectid: 'S-1-5-21-TEST-3703'}),
      (login:MSSQL_Login {name: 'TEST\\sharedsid'}),
      (srvA1:MSSQL_Server {objectid: 'S-1-5-21-TEST-SHARED:1433'}),
      (srvB:MSSQL_Server {name: 'sccmdb.test.local:1433'}),
      (srvBStub:MSSQL_Server {name: 'sccmdb.test.local'}),
      (stub:MSSQL_Base {objectid: 'S-1-5-21-TEST-SHARED:INST2'}),
      (role:MSSQL_ServerRole {SQLServer: 'sccmdb.test.local:1433'})
CREATE (u)-[:MSSQL_HasLogin]->(login)
CREATE (login)-[:MSSQL_Connect]->(srvA1)
CREATE (stub)-[:MSSQL_LinkedAsAdmin]->(srvBStub)
CREATE (srvB)-[:MSSQL_Contains]->(role);
