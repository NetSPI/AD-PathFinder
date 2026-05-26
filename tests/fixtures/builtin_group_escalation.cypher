// Positive: Domain Users group has GenericAll on an enabled computer.

CREATE (g:Group {
  name: 'DOMAIN USERS@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-513',
  domain: 'TEST.LOCAL'
});

CREATE (c:Computer {
  name: 'TARGET01.TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-5101',
  samaccountname: 'TARGET01$',
  enabled: true,
  domain: 'TEST.LOCAL'
});

MATCH (g:Group {objectid: 'S-1-5-21-TEST-513'}),
      (c:Computer {objectid: 'S-1-5-21-TEST-5101'})
CREATE (g)-[:GenericAll]->(c);
