// An empty-named SCCM linked-server target stub must resolve to nothing, not
// to an unrelated MSSQL_Server that backs an SCCM site database.

CREATE (site:SCCM_Site:SCCM_Base:Base {
  siteCode: 'P11',
  displayName: 'Primary Site',
  objectid: 'P11',
  sourceForest: 'TEST.LOCAL'
});

CREATE (srvA:MSSQL_Server:MSSQL_Base:Base {
  name: 'empty-src.test.local:1433',
  sqlServerName: 'empty-src\\SRCINST'
});
CREATE (stub:MSSQL_Base {name: 'LinkedServer:EMPTY-SRC\\SRCINST'});
CREATE (srvBStub:MSSQL_Server:MSSQL_Base:Base {name: ''});

CREATE (unrelated:MSSQL_Server:MSSQL_Base:Base {name: 'unrelated-cm.test.local:1433'});
CREATE (unrelatedRole:MSSQL_ServerRole:MSSQL_Base:Base {name: 'sysadmin', SQLServer: 'unrelated-cm.test.local:1433'});
CREATE (unrelatedDb:MSSQL_Database:MSSQL_Base:Base {name: 'CM_P11', SQLServer: 'unrelated-cm.test.local:1433'});

CREATE (u:User:Base {name: 'SCCMEMPTYSTUB@TEST.LOCAL', objectid: 'S-1-5-21-TEST-311', enabled: true, domain: 'TEST.LOCAL'});
CREATE (login:MSSQL_Login:MSSQL_Base:Base {name: 'TEST\\sccmemptystub', SQLServer: 'empty-src.test.local:1433'});

MATCH (site:SCCM_Site {siteCode: 'P11'}),
      (u:User {objectid: 'S-1-5-21-TEST-311'}),
      (login:MSSQL_Login {name: 'TEST\\sccmemptystub'}),
      (srvA:MSSQL_Server {name: 'empty-src.test.local:1433'}),
      (stub:MSSQL_Base {name: 'LinkedServer:EMPTY-SRC\\SRCINST'}),
      (srvBStub:MSSQL_Server {name: ''}),
      (unrelated:MSSQL_Server {name: 'unrelated-cm.test.local:1433'}),
      (unrelatedRole:MSSQL_ServerRole {SQLServer: 'unrelated-cm.test.local:1433'}),
      (unrelatedDb:MSSQL_Database {name: 'CM_P11'})
CREATE (u)-[:MSSQL_HasLogin]->(login)
CREATE (login)-[:MSSQL_Connect]->(srvA)
CREATE (stub)-[:MSSQL_LinkedAsAdmin]->(srvBStub)
CREATE (unrelated)-[:MSSQL_Contains]->(unrelatedRole)
CREATE (unrelated)-[:MSSQL_Contains]->(unrelatedDb)
CREATE (unrelatedDb)-[:SCCM_AssignAllPermissions]->(site);
