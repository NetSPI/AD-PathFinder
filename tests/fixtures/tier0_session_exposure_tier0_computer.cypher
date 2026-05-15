// Tier-0 session exposure negative: the computer is also tagged admin_tier_0,
// so this is a legitimate session and should not be flagged.

CREATE (u:User {
  name: 'TIERADMIN@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-4001',
  enabled: true,
  domain: 'TEST.LOCAL',
  system_tags: 'admin_tier_0'
});

CREATE (c:Computer {
  name: 'DC01.TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-4002',
  samaccountname: 'DC01$',
  enabled: true,
  domain: 'TEST.LOCAL',
  system_tags: 'admin_tier_0'
});

MATCH (c:Computer {objectid: 'S-1-5-21-TEST-4002'}),
      (u:User {objectid: 'S-1-5-21-TEST-4001'})
CREATE (c)-[:HasSession]->(u);
