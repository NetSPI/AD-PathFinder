// Empty linked-server stub names must not match every MSSQL_Server.

CREATE (srvA:MSSQL_Server {
  name: 'empty-src.test.local:1433',
  sqlServerName: 'empty-src\\SRCINST'
});

CREATE (stub:MSSQL_Base {name: 'LinkedServer:EMPTY-SRC\\SRCINST'});

CREATE (srvBStub:MSSQL_Server {name: ''});

CREATE (unrelated:MSSQL_Server {name: 'unrelated.test.local:1433'});
CREATE (unrelatedRole:MSSQL_ServerRole {name: 'sysadmin', SQLServer: 'unrelated.test.local:1433'});

CREATE (u:User {
  name: 'EMPTYSTUB@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-3702',
  enabled: true,
  domain: 'TEST.LOCAL'
});

CREATE (login:MSSQL_Login {
  name: 'TEST\\emptystub',
  SQLServer: 'empty-src.test.local:1433'
});

MATCH (u:User {objectid: 'S-1-5-21-TEST-3702'}),
      (login:MSSQL_Login {name: 'TEST\\emptystub'}),
      (srvA:MSSQL_Server {name: 'empty-src.test.local:1433'}),
      (stub:MSSQL_Base {name: 'LinkedServer:EMPTY-SRC\\SRCINST'}),
      (srvBStub:MSSQL_Server {name: ''}),
      (unrelated:MSSQL_Server {name: 'unrelated.test.local:1433'}),
      (unrelatedRole:MSSQL_ServerRole {SQLServer: 'unrelated.test.local:1433'})
CREATE (u)-[:MSSQL_HasLogin]->(login)
CREATE (login)-[:MSSQL_Connect]->(srvA)
CREATE (stub)-[:MSSQL_LinkedAsAdmin]->(srvBStub)
CREATE (unrelated)-[:MSSQL_Contains]->(unrelatedRole);
