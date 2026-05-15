// ESC2 positive: template with Any Purpose EKU enrollable by low-priv group.

CREATE (u:User {name: 'alice@TEST.LOCAL', objectid: 'S-1-5-21-TEST-1100', enabled: true, domain: 'TEST.LOCAL'});

CREATE (t:CertTemplate {
  name: 'AnyPurpose@TEST.LOCAL',
  effectiveekus: ['2.5.29.37.0'],
  requiresmanagerapproval: false,
  authorizedsignatures: 0
});

CREATE (ca:EnterpriseCA {caname: 'TEST-CA', dnshostname: 'ca.test.local'});

CREATE (g:Group {name: 'DOMAIN USERS@TEST.LOCAL', objectid: 'S-1-5-21-TEST-513', domain: 'TEST.LOCAL'});

MATCH (g:Group {objectid: 'S-1-5-21-TEST-513'}),
      (t:CertTemplate {name: 'AnyPurpose@TEST.LOCAL'}),
      (ca:EnterpriseCA {caname: 'TEST-CA'})
CREATE (g)-[:Enroll]->(t)
CREATE (t)-[:PublishedTo]->(ca);
