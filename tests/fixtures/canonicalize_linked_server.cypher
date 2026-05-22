// Source-side linked-server stubs: a MSSQL_Base stub carries each linked
// edge. The canonicalizer adds the equivalent edge from the real
// MSSQL_Server that owns the stub's host SID, for both linked-server types.

CREATE (sourceAdmin:MSSQL_Server:MSSQL_Base:Base {
  name: 'src-admin.test.local:1433',
  objectid: 'S-1-5-21-TEST-CANON-A:1433'
});
CREATE (stubAdmin:MSSQL_Base:Base {
  name: 'S-1-5-21-TEST-CANON-A:LINKED',
  objectid: 'S-1-5-21-TEST-CANON-A:LINKED'
});
CREATE (targetAdmin:MSSQL_Server:MSSQL_Base:Base {
  name: 'linked-admin.test.local:1433',
  objectid: 'S-1-5-21-TEST-TGT-A:1433'
});

CREATE (sourceLink:MSSQL_Server:MSSQL_Base:Base {
  name: 'src-link.test.local:1433',
  objectid: 'S-1-5-21-TEST-CANON-B:1433'
});
CREATE (stubLink:MSSQL_Base:Base {
  name: 'S-1-5-21-TEST-CANON-B:LINKED',
  objectid: 'S-1-5-21-TEST-CANON-B:LINKED'
});
CREATE (targetLink:MSSQL_Server:MSSQL_Base:Base {
  name: 'linked-to.test.local:1433',
  objectid: 'S-1-5-21-TEST-TGT-B:1433'
});

MATCH (stubAdmin:MSSQL_Base {objectid: 'S-1-5-21-TEST-CANON-A:LINKED'}),
      (targetAdmin:MSSQL_Server {objectid: 'S-1-5-21-TEST-TGT-A:1433'}),
      (stubLink:MSSQL_Base {objectid: 'S-1-5-21-TEST-CANON-B:LINKED'}),
      (targetLink:MSSQL_Server {objectid: 'S-1-5-21-TEST-TGT-B:1433'})
CREATE (stubAdmin)-[:MSSQL_LinkedAsAdmin]->(targetAdmin)
CREATE (stubLink)-[:MSSQL_LinkedTo]->(targetLink);
