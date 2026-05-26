// Positive: a mid-level login has fan-out (mid -> aaa, mid -> bbb).
// The outer loop iterates source-level targets, so _follow_chain must
// enumerate ALL deeper branches — taking only targets[0] would silently
// drop the second branch.

CREATE (server:MSSQL_Server {name: 'sql02.test.local:1433'});

CREATE (host:Computer {
  name: 'SQL02.TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-2002',
  samaccountname: 'SQL02$',
  enabled: true,
  domain: 'TEST.LOCAL',
  DNSHostName: 'SQL02.TEST.LOCAL'
});

CREATE (src:MSSQL_Login {name: 'TEST\\lowpriv', SQLServer: 'sql02.test.local:1433', type: 'WINDOWS_LOGIN'});
CREATE (mid:MSSQL_Login {name: 'TEST\\mid', SQLServer: 'sql02.test.local:1433', type: 'WINDOWS_LOGIN'});
CREATE (a:MSSQL_Login {name: 'aaa', SQLServer: 'sql02.test.local:1433', type: 'SQL_LOGIN'});
CREATE (b:MSSQL_Login {name: 'bbb', SQLServer: 'sql02.test.local:1433', type: 'SQL_LOGIN'});

MATCH (host:Computer {objectid: 'S-1-5-21-TEST-2002'}),
      (server:MSSQL_Server {name: 'sql02.test.local:1433'})
CREATE (host)-[:MSSQL_HostFor]->(server);

MATCH (server:MSSQL_Server {name: 'sql02.test.local:1433'}),
      (src:MSSQL_Login {name: 'TEST\\lowpriv'}),
      (mid:MSSQL_Login {name: 'TEST\\mid'}),
      (a:MSSQL_Login {name: 'aaa'}),
      (b:MSSQL_Login {name: 'bbb'})
CREATE (server)-[:MSSQL_Contains]->(src)
CREATE (server)-[:MSSQL_Contains]->(mid)
CREATE (server)-[:MSSQL_Contains]->(a)
CREATE (server)-[:MSSQL_Contains]->(b)
CREATE (src)-[:MSSQL_ExecuteAs]->(mid)
CREATE (mid)-[:MSSQL_ExecuteAs]->(a)
CREATE (mid)-[:MSSQL_ExecuteAs]->(b);
