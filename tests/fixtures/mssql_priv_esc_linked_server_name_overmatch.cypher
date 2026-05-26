// Target stub name sql01 must not match the sibling host sql01b.

CREATE (srvA:MSSQL_Server {
  name: 'lab-src.test.local:1433',
  sqlServerName: 'lab-src\\SRCINST'
});

CREATE (srvBStub:MSSQL_Server {name: 'sql01'});

CREATE (srvBIntended:MSSQL_Server {name: 'sql01.test.local:1433'});
CREATE (intendedRole:MSSQL_ServerRole {name: 'sysadmin', SQLServer: 'sql01.test.local:1433'});

CREATE (srvBDecoy:MSSQL_Server {name: 'sql01b.test.local:1433'});
CREATE (decoyRole:MSSQL_ServerRole {name: 'sysadmin', SQLServer: 'sql01b.test.local:1433'});

CREATE (u:User {
  name: 'NAMEOVERMATCH@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-3701',
  enabled: true,
  domain: 'TEST.LOCAL'
});

CREATE (login:MSSQL_Login {
  name: 'TEST\\nameovermatch',
  SQLServer: 'lab-src.test.local:1433'
});

MATCH (u:User {objectid: 'S-1-5-21-TEST-3701'}),
      (login:MSSQL_Login {name: 'TEST\\nameovermatch'}),
      (srvA:MSSQL_Server {name: 'lab-src.test.local:1433'}),
      (srvBStub:MSSQL_Server {name: 'sql01'}),
      (srvBIntended:MSSQL_Server {name: 'sql01.test.local:1433'}),
      (intendedRole:MSSQL_ServerRole {SQLServer: 'sql01.test.local:1433'}),
      (srvBDecoy:MSSQL_Server {name: 'sql01b.test.local:1433'}),
      (decoyRole:MSSQL_ServerRole {SQLServer: 'sql01b.test.local:1433'})
CREATE (u)-[:MSSQL_HasLogin]->(login)
CREATE (login)-[:MSSQL_Connect]->(srvA)
CREATE (srvA)-[:MSSQL_LinkedAsAdmin]->(srvBStub)
CREATE (srvBIntended)-[:MSSQL_Contains]->(intendedRole)
CREATE (srvBDecoy)-[:MSSQL_Contains]->(decoyRole);
