// Tier E positive: two users with SPNs. Admin/weak-password signals come
// from the fake AccountAnalysis the test injects.

CREATE (u1:User {
  name: 'ALICE@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-2400',
  enabled: true,
  domain: 'TEST.LOCAL',
  hasspn: true
});

CREATE (u2:User {
  name: 'BOB@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-2401',
  enabled: true,
  domain: 'TEST.LOCAL',
  hasspn: true
});
