// Cross-domain: a non-tier-0 computer in TEST.LOCAL with a GenericAll
// path to DOMAIN ADMINS in OTHER.LOCAL.

CREATE (c:Computer {
  name: 'WS01.TEST.LOCAL',
  DNSHostName: 'ws01.test.local',
  samaccountname: 'WS01$',
  objectid: 'S-1-5-21-TEST-4100',
  enabled: true,
  domain: 'TEST.LOCAL'
});

CREATE (da:Group {
  name: 'DOMAIN ADMINS@OTHER.LOCAL',
  objectid: 'S-1-5-21-OTHER-512',
  domain: 'OTHER.LOCAL'
});

MATCH (c:Computer {objectid: 'S-1-5-21-TEST-4100'}),
      (da:Group {objectid: 'S-1-5-21-OTHER-512'})
CREATE (c)-[:GenericAll]->(da);
