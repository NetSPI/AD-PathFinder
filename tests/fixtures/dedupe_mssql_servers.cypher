CREATE (a1:MSSQL_Server:MSSQL_Base:Base {
  objectid: 'sccmdb:1433',
  name: 'sccmdb.training.local:1433',
  sqlServerName: 'SCCMDB',
  version: '15.0.4322.2'
});
CREATE (a2:MSSQL_Server:MSSQL_Base:Base {
  objectid: 'S-1-5-21-1105:1433',
  name: 'SCCMDB.training.local:1433',
  xpCmdShellEnabled: false
});
CREATE (a3:MSSQL_Server:MSSQL_Base:Base {
  objectid: 'sccmdb.training.local:1433',
  name: 'SCCMDB.training.local:1433',
  extendedProtection: 'Off'
});

CREATE (b1:MSSQL_Server:MSSQL_Base:Base {
  objectid: 'sql01\\app1:1444',
  name: 'sql01.training.local:1444',
  instanceName: 'APP1'
});
CREATE (b2:MSSQL_Server:MSSQL_Base:Base {
  objectid: 'sql01\\app2:1455',
  name: 'sql01.training.local:1455',
  instanceName: 'APP2'
});
CREATE (b3:MSSQL_Server:MSSQL_Base:Base {
  objectid: 'sql01\\sql01:1433',
  name: 'sql01.training.local:1433',
  instanceName: 'SQL01'
});

CREATE (role:MSSQL_ServerRole:MSSQL_Base:Base {
  objectid: 'sysadmin@S-1-5-21-1105:1433',
  name: 'sysadmin',
  SQLServer: 'SCCMDB.training.local:1433'
});

MATCH (canonical:MSSQL_Server {objectid: 'sccmdb:1433'}),
      (stale:MSSQL_Server {objectid: 'S-1-5-21-1105:1433'}),
      (role:MSSQL_ServerRole {name: 'sysadmin'})
CREATE (canonical)-[:MSSQL_Contains {traversable: true}]->(role)
CREATE (stale)-[:MSSQL_Contains {traversable: true}]->(role);
