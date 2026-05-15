// Positive: a SQL server has a linked server where any login maps to sa
// with sysadmin and RPC enabled.

CREATE (server:MSSQL_Server {name: 'sql01.test.local:1433'});

CREATE (host:Computer {
  name: 'SQL01.TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-2101',
  samaccountname: 'SQL01$',
  enabled: true,
  domain: 'TEST.LOCAL',
  DNSHostName: 'SQL01.TEST.LOCAL'
});

CREATE (target:MSSQL_Server {name: 'sql02.test.local:1433'});

MATCH (host:Computer {objectid: 'S-1-5-21-TEST-2101'}),
      (server:MSSQL_Server {name: 'sql01.test.local:1433'})
CREATE (host)-[:MSSQL_HostFor]->(server);

MATCH (source:MSSQL_Server {name: 'sql01.test.local:1433'}),
      (target:MSSQL_Server {name: 'sql02.test.local:1433'})
CREATE (source)-[:MSSQL_LinkedTo {
  localLogin: 'All Logins',
  remoteCurrentLogin: 'sa',
  remoteIsSysadmin: true,
  rpcOut: true,
  path: 'sql01 -> sql02'
}]->(target);
