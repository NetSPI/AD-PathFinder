// Tier E positive: one enabled domain user. The "admin" and "weak password"
// signals come from the fake AccountAnalysis the test injects, not the graph.

CREATE (u:User {
  name: 'alice@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-1500',
  enabled: true,
  domain: 'TEST.LOCAL'
});

CREATE (u2:User {
  name: 'bob@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-1501',
  enabled: true,
  domain: 'TEST.LOCAL'
});

CREATE (u3:User {
  name: 'carol@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-1502',
  enabled: true,
  domain: 'TEST.LOCAL'
});
