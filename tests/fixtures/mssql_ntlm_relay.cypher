// Positive: MSSQL server running under a domain service account, with a
// Windows login and a well-known group login. A second computer has SMB
// signing disabled, making it a relay target.

CREATE (d:Domain {name: 'TEST.LOCAL', objectid: 'S-1-5-21-TEST', netbios: 'TEST'});

CREATE (server:MSSQL_Server {
  name: 'sql01.test.local:1433',
  serviceAccount: 'TEST\\sqlsvc'
});

CREATE (host:Computer {
  name: 'SQL01.TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-3001',
  samaccountname: 'SQL01$',
  enabled: true,
  domain: 'TEST.LOCAL',
  smbsigning: true,
  operatingsystem: 'Windows Server 2019'
});

CREATE (svcUser:User {
  name: 'SQLSVC@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-3002',
  samaccountname: 'sqlsvc',
  enabled: true,
  domain: 'TEST.LOCAL'
});

CREATE (login:MSSQL_Login {
  name: 'TEST\\jdoe',
  SQLServer: 'sql01.test.local:1433',
  type: 'WINDOWS_LOGIN'
});

CREATE (g:Group {
  name: 'DOMAIN USERS@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-513',
  domain: 'TEST.LOCAL'
});

CREATE (gLogin:MSSQL_Login {
  name: 'TEST\\Domain Users',
  SQLServer: 'sql01.test.local:1433',
  type: 'WINDOWS_GROUP'
});

CREATE (relay:Computer {
  name: 'WEB01.TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-3003',
  samaccountname: 'WEB01$',
  enabled: true,
  domain: 'TEST.LOCAL',
  smbsigning: false,
  operatingsystem: 'Windows Server 2022'
});

// Wire host -> server
MATCH (host:Computer {objectid: 'S-1-5-21-TEST-3001'}),
      (server:MSSQL_Server {name: 'sql01.test.local:1433'})
CREATE (host)-[:MSSQL_HostFor]->(server);

// Wire group -> login
MATCH (g:Group {objectid: 'S-1-5-21-TEST-513'}),
      (gLogin:MSSQL_Login {name: 'TEST\\Domain Users'})
CREATE (g)-[:MSSQL_HasLogin]->(gLogin);
