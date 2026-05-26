// Positive: a Tier-0 admin user has an active session on a non-Tier-0 host.

CREATE (u:User {
  name: 'TIERADMIN@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-4001',
  enabled: true,
  domain: 'TEST.LOCAL',
  system_tags: 'admin_tier_0'
});

CREATE (c:Computer {
  name: 'WS01.TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-4002',
  samaccountname: 'WS01$',
  enabled: true,
  domain: 'TEST.LOCAL'
});

MATCH (c:Computer {objectid: 'S-1-5-21-TEST-4002'}),
      (u:User {objectid: 'S-1-5-21-TEST-4001'})
CREATE (c)-[:HasSession]->(u);
