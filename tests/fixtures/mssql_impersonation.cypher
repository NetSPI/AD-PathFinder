// Positive: a login can EXECUTE AS another login on a hosted SQL server.
// Three-node chain exercises _follow_chain(): lowpriv -> miduser -> sa.

CREATE (server:MSSQL_Server {name: 'sql01.test.local:1433'});

CREATE (host:Computer {
  name: 'SQL01.TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-2001',
  samaccountname: 'SQL01$',
  enabled: true,
  domain: 'TEST.LOCAL',
  DNSHostName: 'SQL01.TEST.LOCAL'
});

CREATE (srcLogin:MSSQL_Login {
  name: 'TEST\\lowpriv',
  SQLServer: 'sql01.test.local:1433',
  type: 'WINDOWS_LOGIN'
});

CREATE (midLogin:MSSQL_Login {
  name: 'TEST\\miduser',
  SQLServer: 'sql01.test.local:1433',
  type: 'WINDOWS_LOGIN'
});

CREATE (tgtLogin:MSSQL_Login {
  name: 'sa',
  SQLServer: 'sql01.test.local:1433',
  type: 'SQL_LOGIN'
});

MATCH (host:Computer {objectid: 'S-1-5-21-TEST-2001'}),
      (server:MSSQL_Server {name: 'sql01.test.local:1433'})
CREATE (host)-[:MSSQL_HostFor]->(server);

MATCH (server:MSSQL_Server {name: 'sql01.test.local:1433'}),
      (srcLogin:MSSQL_Login {name: 'TEST\\lowpriv'}),
      (midLogin:MSSQL_Login {name: 'TEST\\miduser'}),
      (tgtLogin:MSSQL_Login {name: 'sa'})
CREATE (server)-[:MSSQL_Contains]->(srcLogin)
CREATE (server)-[:MSSQL_Contains]->(midLogin)
CREATE (srcLogin)-[:MSSQL_ExecuteAs]->(midLogin)
CREATE (midLogin)-[:MSSQL_ExecuteAs]->(tgtLogin);
