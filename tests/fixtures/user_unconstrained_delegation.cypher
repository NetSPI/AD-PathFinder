// Positive: service account with unconstrained delegation.

CREATE (u:User {
  name: 'SVC-BACKUP@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-1100',
  enabled: true,
  domain: 'TEST.LOCAL',
  unconstraineddelegation: true
});
