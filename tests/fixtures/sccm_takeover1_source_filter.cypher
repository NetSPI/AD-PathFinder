// TAKEOVER-1 negative: out-of-domain and disabled AD coercion sources must not
// create a finding for an in-scope SCCM site database path.

CREATE (site:SCCM_Site {siteCode: 'P01', sourceForest: 'TEST.LOCAL'});
CREATE (server:MSSQL_Server {name: 'sql01.test.local:1433', extendedProtection: false});

CREATE (login:MSSQL_Login {name: 'TEST\\sccmadmin', SQLServer: 'sql01.test.local:1433', type: 'WINDOWS_LOGIN'});
CREATE (role:MSSQL_ServerRole {name: 'sysadmin', SQLServer: 'sql01.test.local:1433'});
CREATE (db:MSSQL_Database {name: 'CM_P01', SQLServer: 'sql01.test.local:1433'});

CREATE (foreignGroup:Group {
  name: 'FOREIGN HELPERS@OTHER.LOCAL',
  objectid: 'S-1-5-21-OTHER-1701',
  domain: 'OTHER.LOCAL'
});

CREATE (disabledSource:Computer {
  name: 'DISABLED-SOURCE.TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-1702',
  samaccountname: 'DISABLED-SOURCE$',
  enabled: false,
  domain: 'TEST.LOCAL'
});

CREATE (target:Computer {
  name: 'SQLHOST.TEST.LOCAL',
  DNSHostName: 'sqlhost.test.local',
  samaccountname: 'SQLHOST$',
  objectid: 'S-1-5-21-TEST-1700',
  enabled: true,
  domain: 'TEST.LOCAL'
});

MATCH (foreignGroup:Group {objectid: 'S-1-5-21-OTHER-1701'}),
      (login:MSSQL_Login {name: 'TEST\\sccmadmin'})
CREATE (foreignGroup)-[:CoerceAndRelayToMSSQL {
  coercionVictimAndRelayTargetPairs: ['Coerce foreign.other.local, relay to sql01.test.local:1433']
}]->(login);

MATCH (disabledSource:Computer {objectid: 'S-1-5-21-TEST-1702'}),
      (login:MSSQL_Login {name: 'TEST\\sccmadmin'})
CREATE (disabledSource)-[:CoerceAndRelayToMSSQL {
  coercionVictimAndRelayTargetPairs: ['Coerce disabled-source.test.local, relay to sql01.test.local:1433']
}]->(login);

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
