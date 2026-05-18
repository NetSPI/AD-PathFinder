// Tier E positive: a non-builtin group with a member and a GenericAll
// relationship to an enabled computer. The group must not be in the
// admin-group or well-known-SID exclusion lists.

CREATE (g:Group {
  name: 'HELPDESK@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-3200',
  domain: 'TEST.LOCAL'
});

CREATE (u:User {
  name: 'ALICE@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-3201',
  enabled: true,
  domain: 'TEST.LOCAL'
});

CREATE (c:Computer {
  name: 'SRV01.TEST.LOCAL',
  DNSHostName: 'srv01.test.local',
  samaccountname: 'SRV01$',
  objectid: 'S-1-5-21-TEST-3202',
  enabled: true,
  domain: 'TEST.LOCAL'
});

MATCH (u:User {objectid: 'S-1-5-21-TEST-3201'}),
      (g:Group {objectid: 'S-1-5-21-TEST-3200'})
CREATE (u)-[:MemberOf]->(g);

MATCH (g:Group {objectid: 'S-1-5-21-TEST-3200'}),
      (c:Computer {objectid: 'S-1-5-21-TEST-3202'})
CREATE (g)-[:GenericAll]->(c);
