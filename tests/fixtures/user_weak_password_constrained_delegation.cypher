// Tier E positive: one user with constrained delegation targets, one without.
// Weak-password signal comes from the fake AccountAnalysis the test injects.

CREATE (u1:User {
  name: 'ALICE@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-2600',
  enabled: true,
  domain: 'TEST.LOCAL',
  allowedtodelegate: ['cifs/target.test.local']
});

CREATE (u2:User {
  name: 'BOB@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-2601',
  enabled: true,
  domain: 'TEST.LOCAL'
});
