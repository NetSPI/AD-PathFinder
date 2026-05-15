// Tier E positive: two enabled users. The escalation-path signal lives in the
// shared cache the test injects. Admin status comes from fake AccountAnalysis.

CREATE (u1:User {
  name: 'ALICE@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-3100',
  enabled: true,
  domain: 'TEST.LOCAL'
});

CREATE (u2:User {
  name: 'BOB@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-3101',
  enabled: true,
  domain: 'TEST.LOCAL'
});
