// TAKEOVER-2 positive: SMB relay from site server to remote site database host.
// Hybrid: target Computer hosts MSSQL_Server whose DB grants SCCM_AssignAllPermissions.

CREATE (site:SCCM_Site {siteCode: 'P01', sourceForest: 'TEST.LOCAL'});

CREATE (server:MSSQL_Server {name: 'sqldb.test.local:1433'});

CREATE (db:MSSQL_Database {name: 'CM_P01', SQLServer: 'sqldb.test.local:1433'});

CREATE (target:Computer {
  name: 'SQLDB.TEST.LOCAL',
  DNSHostName: 'sqldb.test.local',
  samaccountname: 'SQLDB$',
  objectid: 'S-1-5-21-TEST-1800',
  enabled: true,
  domain: 'TEST.LOCAL',
  SMBSigningRequired: false
});

CREATE (ss:Computer {
  name: 'SITESVR.TEST.LOCAL',
  DNSHostName: 'sitesvr.test.local',
  samaccountname: 'SITESVR$',
  objectid: 'S-1-5-21-TEST-1801',
  enabled: true,
  domain: 'TEST.LOCAL',
  SCCMSiteSystemRoles: ['SMS Site Server@P01']
});

CREATE (g:Group {name: 'AUTHENTICATED USERS@TEST.LOCAL', objectid: 'S-1-5-11', domain: 'TEST.LOCAL'});

MATCH (g:Group {objectid: 'S-1-5-11'}),
      (target:Computer {objectid: 'S-1-5-21-TEST-1800'})
CREATE (g)-[:CoerceAndRelayToSMB]->(target);

MATCH (target:Computer {objectid: 'S-1-5-21-TEST-1800'}),
      (server:MSSQL_Server {name: 'sqldb.test.local:1433'})
CREATE (target)-[:MSSQL_HostFor]->(server);

MATCH (server:MSSQL_Server {name: 'sqldb.test.local:1433'}),
      (db:MSSQL_Database {name: 'CM_P01'})
CREATE (server)-[:MSSQL_Contains]->(db);

MATCH (db:MSSQL_Database {name: 'CM_P01'}),
      (site:SCCM_Site {siteCode: 'P01'})
CREATE (db)-[:SCCM_AssignAllPermissions]->(site);
