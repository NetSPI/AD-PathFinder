// Tier E positive: two enabled users. Admin/weak-password signals come
// from the fake AccountAnalysis the test injects.

CREATE (u1:User {
  name: 'ALICE@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-2000',
  enabled: true,
  domain: 'TEST.LOCAL'
});

CREATE (u2:User {
  name: 'BOB@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-2001',
  enabled: true,
  domain: 'TEST.LOCAL'
});
