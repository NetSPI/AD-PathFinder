// Tier E positive: non-admin user with AdminTo a computer.
// Admin user with the same relationship should be excluded.

CREATE (u1:User {
  name: 'ALICE@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-3000',
  samaccountname: 'alice',
  enabled: true,
  domain: 'TEST.LOCAL'
});

CREATE (u2:User {
  name: 'BOB@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-3001',
  samaccountname: 'bob',
  enabled: true,
  domain: 'TEST.LOCAL'
});

CREATE (c:Computer {
  name: 'SRV01.TEST.LOCAL',
  DNSHostName: 'srv01.test.local',
  samaccountname: 'SRV01$',
  objectid: 'S-1-5-21-TEST-3002',
  enabled: true,
  domain: 'TEST.LOCAL'
});

MATCH (u1:User {objectid: 'S-1-5-21-TEST-3000'}),
      (c:Computer {objectid: 'S-1-5-21-TEST-3002'})
CREATE (u1)-[:AdminTo]->(c);

MATCH (u2:User {objectid: 'S-1-5-21-TEST-3001'}),
      (c:Computer {objectid: 'S-1-5-21-TEST-3002'})
CREATE (u2)-[:AdminTo]->(c);
