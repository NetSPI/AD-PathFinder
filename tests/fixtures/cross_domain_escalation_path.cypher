// Cross-domain: a non-admin user in TEST.LOCAL with a MemberOf path
// to DOMAIN ADMINS in OTHER.LOCAL via an intermediate group.

CREATE (u:User {
  name: 'ALICE@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-4000',
  enabled: true,
  domain: 'TEST.LOCAL'
});

CREATE (g:Group {
  name: 'BRIDGE@OTHER.LOCAL',
  objectid: 'S-1-5-21-OTHER-4001',
  domain: 'OTHER.LOCAL'
});

CREATE (da:Group {
  name: 'DOMAIN ADMINS@OTHER.LOCAL',
  objectid: 'S-1-5-21-OTHER-512',
  domain: 'OTHER.LOCAL'
});

MATCH (u:User {objectid: 'S-1-5-21-TEST-4000'}),
      (g:Group {objectid: 'S-1-5-21-OTHER-4001'})
CREATE (u)-[:MemberOf]->(g);

MATCH (g:Group {objectid: 'S-1-5-21-OTHER-4001'}),
      (da:Group {objectid: 'S-1-5-21-OTHER-512'})
CREATE (g)-[:MemberOf]->(da);
