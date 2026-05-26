// Stub name cmsql must not match the sibling host cmsql-dr.

CREATE (site:SCCM_Site:SCCM_Base:Base {
  siteCode: 'P10',
  displayName: 'Primary Site',
  objectid: 'P10',
  sourceForest: 'TEST.LOCAL'
});

CREATE (srvA:MSSQL_Server:MSSQL_Base:Base {
  name: 'lab-src.test.local:1433',
  sqlServerName: 'lab-src\\SRCINST'
});
CREATE (srvBStub:MSSQL_Server:MSSQL_Base:Base {name: 'cmsql'});

CREATE (srvBIntended:MSSQL_Server:MSSQL_Base:Base {name: 'cmsql.test.local:1433'});
CREATE (intendedRole:MSSQL_ServerRole:MSSQL_Base:Base {name: 'sysadmin', SQLServer: 'cmsql.test.local:1433'});
CREATE (intendedDb:MSSQL_Database:MSSQL_Base:Base {name: 'CM_P10', SQLServer: 'cmsql.test.local:1433'});

CREATE (srvBDecoy:MSSQL_Server:MSSQL_Base:Base {name: 'cmsql-dr.test.local:1433'});
CREATE (decoyRole:MSSQL_ServerRole:MSSQL_Base:Base {name: 'sysadmin', SQLServer: 'cmsql-dr.test.local:1433'});
CREATE (decoyDb:MSSQL_Database:MSSQL_Base:Base {name: 'CM_DR', SQLServer: 'cmsql-dr.test.local:1433'});

CREATE (u:User:Base {name: 'SCCMNAMEOVERMATCH@TEST.LOCAL', objectid: 'S-1-5-21-TEST-310', enabled: true, domain: 'TEST.LOCAL'});
CREATE (login:MSSQL_Login:MSSQL_Base:Base {name: 'TEST\\sccmnameovermatch', SQLServer: 'lab-src.test.local:1433'});

MATCH (site:SCCM_Site {siteCode: 'P10'}),
      (u:User {objectid: 'S-1-5-21-TEST-310'}),
      (login:MSSQL_Login {name: 'TEST\\sccmnameovermatch'}),
      (srvA:MSSQL_Server {name: 'lab-src.test.local:1433'}),
      (srvBStub:MSSQL_Server {name: 'cmsql'}),
      (srvBIntended:MSSQL_Server {name: 'cmsql.test.local:1433'}),
      (intendedRole:MSSQL_ServerRole {SQLServer: 'cmsql.test.local:1433'}),
      (intendedDb:MSSQL_Database {name: 'CM_P10'}),
      (srvBDecoy:MSSQL_Server {name: 'cmsql-dr.test.local:1433'}),
      (decoyRole:MSSQL_ServerRole {SQLServer: 'cmsql-dr.test.local:1433'}),
      (decoyDb:MSSQL_Database {name: 'CM_DR'})
CREATE (u)-[:MSSQL_HasLogin]->(login)
CREATE (login)-[:MSSQL_Connect]->(srvA)
CREATE (srvA)-[:MSSQL_LinkedAsAdmin]->(srvBStub)
CREATE (srvBIntended)-[:MSSQL_Contains]->(intendedRole)
CREATE (srvBIntended)-[:MSSQL_Contains]->(intendedDb)
CREATE (intendedDb)-[:SCCM_AssignAllPermissions]->(site)
CREATE (srvBDecoy)-[:MSSQL_Contains]->(decoyRole)
CREATE (srvBDecoy)-[:MSSQL_Contains]->(decoyDb)
CREATE (decoyDb)-[:SCCM_AssignAllPermissions]->(site);
