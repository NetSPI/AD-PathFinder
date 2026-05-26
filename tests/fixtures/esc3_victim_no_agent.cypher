// ESC3 victim negative: a schema v1 auth-enabled template with low-priv
// enrol exists, but no ESC3.1 agent template is published on the same CA.
// The chain is incomplete, so the victim check must NOT fire.

CREATE (u:User {name: 'alice@TEST.LOCAL', objectid: 'S-1-5-21-TEST-1310', enabled: true, domain: 'TEST.LOCAL'});

CREATE (vV1:CertTemplate {
  name: 'OrphanVictim@TEST.LOCAL',
  authenticationenabled: true,
  requiresmanagerapproval: false,
  authorizedsignatures: 0,
  schemaversion: 1
});

CREATE (ca:EnterpriseCA {caname: 'TEST-CA-2', dnshostname: 'ca2.test.local'});

CREATE (g:Group {name: 'DOMAIN USERS@TEST.LOCAL', objectid: 'S-1-5-21-TEST-513', domain: 'TEST.LOCAL'});

MATCH (g:Group {objectid: 'S-1-5-21-TEST-513'}),
      (vV1:CertTemplate {name: 'OrphanVictim@TEST.LOCAL'}),
      (ca:EnterpriseCA {caname: 'TEST-CA-2'})
CREATE (g)-[:Enroll]->(vV1)
CREATE (vV1)-[:PublishedTo]->(ca);
