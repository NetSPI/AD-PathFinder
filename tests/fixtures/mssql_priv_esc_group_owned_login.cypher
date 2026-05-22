// A low-priv user inherits a SQL login through six nested AD groups.

CREATE (u:User {
  name: 'NESTEDUSER@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-3401',
  enabled: true,
  domain: 'TEST.LOCAL'
});

CREATE (g1:Group {name: 'G1@TEST.LOCAL', objectid: 'S-1-5-21-TEST-G1', domain: 'TEST.LOCAL'});
CREATE (g2:Group {name: 'G2@TEST.LOCAL', objectid: 'S-1-5-21-TEST-G2', domain: 'TEST.LOCAL'});
CREATE (g3:Group {name: 'G3@TEST.LOCAL', objectid: 'S-1-5-21-TEST-G3', domain: 'TEST.LOCAL'});
CREATE (g4:Group {name: 'G4@TEST.LOCAL', objectid: 'S-1-5-21-TEST-G4', domain: 'TEST.LOCAL'});
CREATE (g5:Group {name: 'G5@TEST.LOCAL', objectid: 'S-1-5-21-TEST-G5', domain: 'TEST.LOCAL'});
CREATE (g6:Group {name: 'SQL OWNERS@TEST.LOCAL', objectid: 'S-1-5-21-TEST-G6', domain: 'TEST.LOCAL'});

CREATE (login:MSSQL_Login {
  name: 'TEST\\group-login',
  SQLServer: 'sql01.test.local:1433'
});

CREATE (role:MSSQL_ServerRole {
  name: 'sysadmin',
  SQLServer: 'sql01.test.local:1433'
});

CREATE (server:MSSQL_Server {
  name: 'sql01.test.local:1433',
  xpCmdShellEnabled: false
});

MATCH (u:User {objectid: 'S-1-5-21-TEST-3401'}),
      (g1:Group {objectid: 'S-1-5-21-TEST-G1'}),
      (g2:Group {objectid: 'S-1-5-21-TEST-G2'}),
      (g3:Group {objectid: 'S-1-5-21-TEST-G3'}),
      (g4:Group {objectid: 'S-1-5-21-TEST-G4'}),
      (g5:Group {objectid: 'S-1-5-21-TEST-G5'}),
      (g6:Group {objectid: 'S-1-5-21-TEST-G6'}),
      (login:MSSQL_Login {name: 'TEST\\group-login'}),
      (role:MSSQL_ServerRole {name: 'sysadmin'})
CREATE (u)-[:MemberOf]->(g1)
CREATE (g1)-[:MemberOf]->(g2)
CREATE (g2)-[:MemberOf]->(g3)
CREATE (g3)-[:MemberOf]->(g4)
CREATE (g4)-[:MemberOf]->(g5)
CREATE (g5)-[:MemberOf]->(g6)
CREATE (g6)-[:MSSQL_HasLogin]->(login)
CREATE (login)-[:MSSQL_MemberOf]->(role);
