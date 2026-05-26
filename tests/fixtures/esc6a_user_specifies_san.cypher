// ESC6a positive: CA has EDITF flag, template is auth-enabled, low-priv enrolment.
// Template has SID security extension set (nse=false) so ESC6b would NOT fire,
// but ESC6a is exploitable on pre-patch DCs regardless.

CREATE (u:User {name: 'alice@TEST.LOCAL', objectid: 'S-1-5-21-TEST-1100', enabled: true, domain: 'TEST.LOCAL'});

CREATE (t:CertTemplate {
  name: 'PrePatch@TEST.LOCAL',
  nosecurityextension: false,
  authenticationenabled: true,
  requiresmanagerapproval: false,
  authorizedsignatures: 0
});

CREATE (ca:EnterpriseCA {caname: 'TEST-CA', dnshostname: 'ca.test.local', isuserspecifiessanenabled: true});

CREATE (g:Group {name: 'DOMAIN USERS@TEST.LOCAL', objectid: 'S-1-5-21-TEST-513', domain: 'TEST.LOCAL'});

MATCH (g:Group {objectid: 'S-1-5-21-TEST-513'}),
      (t:CertTemplate {name: 'PrePatch@TEST.LOCAL'}),
      (ca:EnterpriseCA {caname: 'TEST-CA'})
CREATE (g)-[:Enroll]->(t)
CREATE (t)-[:PublishedTo]->(ca);
