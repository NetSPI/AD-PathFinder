// ESC9 negative: same shape as the positive fixture, but authentication is
// disabled on the template. Check should stay silent.

CREATE (u:User {name: 'alice@TEST.LOCAL', objectid: 'S-1-5-21-TEST-1100', enabled: true, domain: 'TEST.LOCAL'});

CREATE (t:CertTemplate {
  name: 'NoSecExt@TEST.LOCAL',
  nosecurityextension: true,
  authenticationenabled: false,
  requiresmanagerapproval: false,
  authorizedsignatures: 0
});

CREATE (ca:EnterpriseCA {caname: 'TEST-CA', dnshostname: 'ca.test.local'});

CREATE (g:Group {name: 'DOMAIN USERS@TEST.LOCAL', objectid: 'S-1-5-21-TEST-513', domain: 'TEST.LOCAL'});

MATCH (g:Group {objectid: 'S-1-5-21-TEST-513'}),
      (t:CertTemplate {name: 'NoSecExt@TEST.LOCAL'}),
      (ca:EnterpriseCA {caname: 'TEST-CA'})
CREATE (g)-[:Enroll]->(t)
CREATE (t)-[:PublishedTo]->(ca);
