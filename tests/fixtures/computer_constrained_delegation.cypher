// Positive: computer configured for constrained delegation.

CREATE (c:Computer {
  name: 'WS01.TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-1001',
  samaccountname: 'WS01$',
  enabled: true,
  domain: 'TEST.LOCAL',
  allowedtodelegate: ['MSSQLSvc/sql.test.local:1433']
});
