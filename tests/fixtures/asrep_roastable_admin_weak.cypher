// Tier E positive: two users with pre-auth disabled. Admin/weak-password
// signals come from the fake AccountAnalysis the test injects.

CREATE (u1:User {
  name: 'ALICE@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-2200',
  enabled: true,
  domain: 'TEST.LOCAL',
  dontreqpreauth: true
});

CREATE (u2:User {
  name: 'BOB@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-2201',
  enabled: true,
  domain: 'TEST.LOCAL',
  dontreqpreauth: true
});
