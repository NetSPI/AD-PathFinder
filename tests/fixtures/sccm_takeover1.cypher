// TAKEOVER-1 positive: NTLM relay to SCCM site database via MSSQL chain.
// Hybrid: needs both SCCM_Site and MSSQL_Server sentinels.

CREATE (site:SCCM_Site {siteCode: 'P01', sourceForest: 'TEST.LOCAL'});
CREATE (server:MSSQL_Server {name: 'sql01.test.local:1433', extendedProtection: false});

CREATE (login:MSSQL_Login {name: 'TEST\\sccmadmin', SQLServer: 'sql01.test.local:1433', type: 'WINDOWS_LOGIN'});
CREATE (role:MSSQL_ServerRole {name: 'sysadmin', SQLServer: 'sql01.test.local:1433'});
CREATE (db:MSSQL_Database {name: 'CM_P01', SQLServer: 'sql01.test.local:1433'});

CREATE (g:Group {name: 'AUTHENTICATED USERS@TEST.LOCAL', objectid: 'S-1-5-11', domain: 'TEST.LOCAL'});

CREATE (target:Computer {
  name: 'SQLHOST.TEST.LOCAL',
  DNSHostName: 'sqlhost.test.local',
  samaccountname: 'SQLHOST$',
  objectid: 'S-1-5-21-TEST-1700',
  enabled: true,
  domain: 'TEST.LOCAL'
});

MATCH (g:Group {objectid: 'S-1-5-11'}),
      (login:MSSQL_Login {name: 'TEST\\sccmadmin'})
CREATE (g)-[:CoerceAndRelayToMSSQL {coercionVictimAndRelayTargetPairs: ['Coerce siteserver.test.local, relay to sql01.test.local:1433']}]->(login);

MATCH (login:MSSQL_Login {name: 'TEST\\sccmadmin'}),
      (role:MSSQL_ServerRole {name: 'sysadmin'})
CREATE (login)-[:MSSQL_MemberOf]->(role);

MATCH (role:MSSQL_ServerRole {name: 'sysadmin'}),
      (server:MSSQL_Server {name: 'sql01.test.local:1433'})
CREATE (role)-[:MSSQL_ControlServer]->(server);

MATCH (login:MSSQL_Login {name: 'TEST\\sccmadmin'}),
      (db:MSSQL_Database {name: 'CM_P01'})
CREATE (login)-[:MSSQL_ControlDB]->(db);

MATCH (db:MSSQL_Database {name: 'CM_P01'}),
      (site:SCCM_Site {siteCode: 'P01'})
CREATE (db)-[:SCCM_AssignAllPermissions]->(site);

MATCH (target:Computer {objectid: 'S-1-5-21-TEST-1700'}),
      (server:MSSQL_Server {name: 'sql01.test.local:1433'})
CREATE (target)-[:MSSQL_HostFor]->(server);
