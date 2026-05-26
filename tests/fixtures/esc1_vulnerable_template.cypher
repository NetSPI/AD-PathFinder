// ESC1 positive: low-priv group can enroll in a template that allows
// enrollee-supplied subject with client auth EKU.

CREATE (u:User {name: 'alice@TEST.LOCAL', objectid: 'S-1-5-21-TEST-1100', enabled: true, domain: 'TEST.LOCAL'});

CREATE (t:CertTemplate {
  name: 'VulnTemplate@TEST.LOCAL',
  enrolleesuppliessubject: true,
  authenticationenabled: true,
  requiresmanagerapproval: false,
  authorizedsignatures: 0
});

CREATE (ca:EnterpriseCA {caname: 'TEST-CA', dnshostname: 'ca.test.local'});

CREATE (g:Group {name: 'DOMAIN USERS@TEST.LOCAL', objectid: 'S-1-5-21-TEST-513', domain: 'TEST.LOCAL'});

MATCH (g:Group {objectid: 'S-1-5-21-TEST-513'}),
      (t:CertTemplate {name: 'VulnTemplate@TEST.LOCAL'}),
      (ca:EnterpriseCA {caname: 'TEST-CA'})
CREATE (g)-[:Enroll]->(t)
CREATE (t)-[:PublishedTo]->(ca);
