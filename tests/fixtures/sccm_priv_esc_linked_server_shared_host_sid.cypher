// Two SQL instances share a host SID. The SCCM linked path must bridge to
// neither when the stub objectid host SID is ambiguous.

CREATE (site:SCCM_Site:SCCM_Base:Base {
  siteCode: 'P12',
  displayName: 'Primary Site',
  objectid: 'P12',
  sourceForest: 'TEST.LOCAL'
});

CREATE (srvA1:MSSQL_Server:MSSQL_Base:Base {
  name: 'shared-host.test.local:1433',
  sqlServerName: 'shared-host\\INST1',
  objectid: 'S-1-5-21-TEST-SHARED:1433'
});
CREATE (srvA2:MSSQL_Server:MSSQL_Base:Base {
  name: 'shared-host.test.local:1434',
  sqlServerName: 'shared-host\\INST2',
  objectid: 'S-1-5-21-TEST-SHARED:1434'
});

CREATE (stub:MSSQL_Base {name: 'S-1-5-21-TEST-SHARED:INST2', objectid: 'S-1-5-21-TEST-SHARED:INST2'});

CREATE (srvBStub:MSSQL_Server:MSSQL_Base:Base {name: 'cmsql.test.local'});
CREATE (srvB:MSSQL_Server:MSSQL_Base:Base {name: 'cmsql.test.local:1433'});
CREATE (role:MSSQL_ServerRole:MSSQL_Base:Base {name: 'sysadmin', SQLServer: 'cmsql.test.local:1433'});
CREATE (sccmDb:MSSQL_Database:MSSQL_Base:Base {name: 'CM_P12', SQLServer: 'cmsql.test.local:1433'});

CREATE (u:User:Base {name: 'SCCMSHAREDSID@TEST.LOCAL', objectid: 'S-1-5-21-TEST-312', enabled: true, domain: 'TEST.LOCAL'});
CREATE (login:MSSQL_Login:MSSQL_Base:Base {name: 'TEST\\sccmsharedsid', SQLServer: 'shared-host.test.local:1433'});

MATCH (site:SCCM_Site {siteCode: 'P12'}),
      (u:User {objectid: 'S-1-5-21-TEST-312'}),
      (login:MSSQL_Login {name: 'TEST\\sccmsharedsid'}),
      (srvA1:MSSQL_Server {objectid: 'S-1-5-21-TEST-SHARED:1433'}),
      (stub:MSSQL_Base {objectid: 'S-1-5-21-TEST-SHARED:INST2'}),
      (srvBStub:MSSQL_Server {name: 'cmsql.test.local'}),
      (srvB:MSSQL_Server {name: 'cmsql.test.local:1433'}),
      (role:MSSQL_ServerRole {SQLServer: 'cmsql.test.local:1433'}),
      (sccmDb:MSSQL_Database {name: 'CM_P12'})
CREATE (u)-[:MSSQL_HasLogin]->(login)
CREATE (login)-[:MSSQL_Connect]->(srvA1)
CREATE (stub)-[:MSSQL_LinkedAsAdmin]->(srvBStub)
CREATE (srvB)-[:MSSQL_Contains]->(role)
CREATE (srvB)-[:MSSQL_Contains]->(sccmDb)
CREATE (sccmDb)-[:SCCM_AssignAllPermissions]->(site);
