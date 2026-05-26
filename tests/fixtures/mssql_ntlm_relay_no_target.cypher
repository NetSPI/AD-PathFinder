// Negative: MSSQL server with a resolvable service account and a login,
// but every Windows host enforces SMB signing. With no relay target the
// chain cannot complete, so the check must emit zero findings.

CREATE (d:Domain {name: 'TEST.LOCAL', objectid: 'S-1-5-21-TEST', netbios: 'TEST'});

CREATE (server:MSSQL_Server {
  name: 'sql02.test.local:1433',
  serviceAccount: 'TEST\\sqlsvc'
});

CREATE (host:Computer {
  name: 'SQL02.TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-3101',
  samaccountname: 'SQL02$',
  enabled: true,
  domain: 'TEST.LOCAL',
  smbsigning: true,
  operatingsystem: 'Windows Server 2019'
});

CREATE (svcUser:User {
  name: 'SQLSVC@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-3102',
  samaccountname: 'sqlsvc',
  enabled: true,
  domain: 'TEST.LOCAL'
});

CREATE (login:MSSQL_Login {
  name: 'TEST\\jdoe',
  SQLServer: 'sql02.test.local:1433',
  type: 'WINDOWS_LOGIN'
});

MATCH (host:Computer {objectid: 'S-1-5-21-TEST-3101'}),
      (server:MSSQL_Server {name: 'sql02.test.local:1433'})
CREATE (host)-[:MSSQL_HostFor]->(server);
