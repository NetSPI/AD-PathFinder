// Positive: a non-admin user has an MSSQL login mapped to a database user
// with db_owner role and ControlDB capability on a non-system database.
// Also includes a well-known group with a login (exercises the group query).

CREATE (server:MSSQL_Server {name: 'sql01.test.local:1433'});

CREATE (u:User {
  name: 'SQLUSER@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-2201',
  enabled: true,
  domain: 'TEST.LOCAL'
});

CREATE (login:MSSQL_Login {
  name: 'TEST\\sqluser',
  SQLServer: 'sql01.test.local:1433',
  type: 'WINDOWS_LOGIN'
});

CREATE (dbUser:MSSQL_DatabaseUser {
  name: 'sqluser',
  database: 'AppDB',
  SQLServer: 'sql01.test.local:1433'
});

CREATE (dbRole:MSSQL_DatabaseRole {
  name: 'db_owner@AppDB',
  SQLServer: 'sql01.test.local:1433'
});

CREATE (db:MSSQL_Database {
  name: 'AppDB',
  SQLServer: 'sql01.test.local:1433'
});

// Well-known group for the group login query path
CREATE (g:Group {
  name: 'DOMAIN USERS@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-513',
  domain: 'TEST.LOCAL'
});

CREATE (gLogin:MSSQL_Login {
  name: 'TEST\\Domain Users',
  SQLServer: 'sql01.test.local:1433',
  type: 'WINDOWS_GROUP'
});

// Wire user -> login -> dbUser -> dbRole -> capability
MATCH (u:User {objectid: 'S-1-5-21-TEST-2201'}),
      (login:MSSQL_Login {name: 'TEST\\sqluser'}),
      (dbUser:MSSQL_DatabaseUser {name: 'sqluser'}),
      (dbRole:MSSQL_DatabaseRole {name: 'db_owner@AppDB'}),
      (db:MSSQL_Database {name: 'AppDB'})
CREATE (u)-[:MSSQL_HasLogin]->(login)
CREATE (login)-[:MSSQL_IsMappedTo]->(dbUser)
CREATE (dbUser)-[:MSSQL_MemberOf]->(dbRole)
CREATE (dbRole)-[:MSSQL_ControlDB]->(db);

// Wire group -> login
MATCH (g:Group {objectid: 'S-1-5-21-TEST-513'}),
      (gLogin:MSSQL_Login {name: 'TEST\\Domain Users'})
CREATE (g)-[:MSSQL_HasLogin]->(gLogin);
