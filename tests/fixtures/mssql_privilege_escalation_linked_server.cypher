// Linked-server admin edge from a real MSSQL_Server source.

CREATE (srvA:MSSQL_Server {
  name: 'lab-sql01.test.local:1433',
  sqlServerName: 'lab-sql01\\SQL01'
});

CREATE (srvB:MSSQL_Server {
  name: 'sccmdb.test.local:1433'
});

CREATE (role:MSSQL_ServerRole {
  name: 'sysadmin',
  SQLServer: 'sccmdb.test.local:1433'
});

CREATE (u:User {
  name: 'LOWPRIV@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-3201',
  enabled: true,
  domain: 'TEST.LOCAL'
});

CREATE (groupUser:User {
  name: 'GROUPLINK@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-3202',
  enabled: true,
  domain: 'TEST.LOCAL'
});

CREATE (broadUser:User {
  name: 'BROADLINK@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-3203',
  enabled: true,
  domain: 'TEST.LOCAL'
});

CREATE (linkedGroup:Group {
  name: 'LINKED SQL USERS@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-LINKED-GROUP',
  domain: 'TEST.LOCAL'
});

CREATE (domainUsers:Group {
  name: 'DOMAIN USERS@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-513',
  domain: 'TEST.LOCAL'
});

CREATE (login:MSSQL_Login {
  name: 'TEST\\lowpriv',
  SQLServer: 'lab-sql01.test.local:1433'
});

CREATE (groupLogin:MSSQL_Login {
  name: 'TEST\\linked-group',
  SQLServer: 'lab-sql01.test.local:1433'
});

CREATE (broadLogin:MSSQL_Login {
  name: 'TEST\\Domain Users',
  SQLServer: 'lab-sql01.test.local:1433'
});

MATCH (u:User {objectid: 'S-1-5-21-TEST-3201'}),
      (groupUser:User {objectid: 'S-1-5-21-TEST-3202'}),
      (broadUser:User {objectid: 'S-1-5-21-TEST-3203'}),
      (linkedGroup:Group {objectid: 'S-1-5-21-TEST-LINKED-GROUP'}),
      (domainUsers:Group {objectid: 'S-1-5-21-TEST-513'}),
      (login:MSSQL_Login {name: 'TEST\\lowpriv'}),
      (groupLogin:MSSQL_Login {name: 'TEST\\linked-group'}),
      (broadLogin:MSSQL_Login {name: 'TEST\\Domain Users'}),
      (srvA:MSSQL_Server {name: 'lab-sql01.test.local:1433'}),
      (srvB:MSSQL_Server {name: 'sccmdb.test.local:1433'}),
      (role:MSSQL_ServerRole {name: 'sysadmin'})
CREATE (u)-[:MSSQL_HasLogin]->(login)
CREATE (login)-[:MSSQL_Connect]->(srvA)
CREATE (groupUser)-[:MemberOf]->(linkedGroup)
CREATE (linkedGroup)-[:MSSQL_HasLogin]->(groupLogin)
CREATE (groupLogin)-[:MSSQL_Connect]->(srvA)
CREATE (broadUser)-[:MemberOf]->(domainUsers)
CREATE (domainUsers)-[:MSSQL_HasLogin]->(broadLogin)
CREATE (broadLogin)-[:MSSQL_Connect]->(srvA)
CREATE (srvA)-[:MSSQL_LinkedAsAdmin]->(srvB)
CREATE (srvB)-[:MSSQL_Contains]->(role);
