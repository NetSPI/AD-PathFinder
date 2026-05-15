// Positive: service account configured for constrained delegation.

CREATE (u:User {
  name: 'SVC-SQL@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-1100',
  enabled: true,
  domain: 'TEST.LOCAL',
  allowedtodelegate: ['MSSQLSvc/sql.test.local:1433']
});
