// ESC3 positive: low-priv group has Enroll on a template with the Certificate
// Request Agent EKU, published to an Enterprise CA.

CREATE (u:User {name: 'alice@TEST.LOCAL', objectid: 'S-1-5-21-TEST-1100', enabled: true, domain: 'TEST.LOCAL'});

CREATE (t:CertTemplate {
  name: 'EnrollAgent@TEST.LOCAL',
  effectiveekus: ['1.3.6.1.4.1.311.20.2.1'],
  requiresmanagerapproval: false,
  authorizedsignatures: 0
});

CREATE (ca:EnterpriseCA {caname: 'TEST-CA', dnshostname: 'ca.test.local'});

// Well-known SID exception: Domain Users must end with -513.
CREATE (g:Group {name: 'DOMAIN USERS@TEST.LOCAL', objectid: 'S-1-5-21-TEST-513', domain: 'TEST.LOCAL'});

MATCH (g:Group {objectid: 'S-1-5-21-TEST-513'}),
      (t:CertTemplate {name: 'EnrollAgent@TEST.LOCAL'}),
      (ca:EnterpriseCA {caname: 'TEST-CA'})
CREATE (g)-[:Enroll]->(t)
CREATE (t)-[:PublishedTo]->(ca);
