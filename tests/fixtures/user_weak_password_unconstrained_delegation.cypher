// Tier E positive: one user with unconstrained delegation, one without.
// Weak-password signal comes from the fake AccountAnalysis the test injects.

CREATE (u1:User {
  name: 'ALICE@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-2700',
  enabled: true,
  domain: 'TEST.LOCAL',
  unconstraineddelegation: true
});

CREATE (u2:User {
  name: 'BOB@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-2701',
  enabled: true,
  domain: 'TEST.LOCAL'
});
