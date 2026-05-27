// ESC3 victim negative (disjoint ACL): an agent template and a victim
// template both exist on the same CA, both pass the structural gates
// (schema v1 victim, Cert Request Agent EKU on agent, etc.), but the
// agent's enrolment ACL only lets Domain Users in and the victim's only
// lets Domain Computers in. No principal can hold both, so the chain is
// not exploitable and the check must NOT fire.

CREATE (alice:User {name: 'alice@TEST.LOCAL', objectid: 'S-1-5-21-TEST-1320', enabled: true, domain: 'TEST.LOCAL'});

CREATE (agent:CertTemplate {
  name: 'Agent@TEST.LOCAL',
  effectiveekus: ['1.3.6.1.4.1.311.20.2.1'],
  authenticationenabled: false,
  requiresmanagerapproval: false,
  authorizedsignatures: 0,
  schemaversion: 2
});

CREATE (victim:CertTemplate {
  name: 'OnlyComputersVictim@TEST.LOCAL',
  authenticationenabled: true,
  requiresmanagerapproval: false,
  authorizedsignatures: 0,
  schemaversion: 1
});

CREATE (ca:EnterpriseCA {caname: 'TEST-CA-3', dnshostname: 'ca3.test.local'});

CREATE (du:Group {name: 'DOMAIN USERS@TEST.LOCAL', objectid: 'S-1-5-21-TEST-513', domain: 'TEST.LOCAL'});
CREATE (dc:Group {name: 'DOMAIN COMPUTERS@TEST.LOCAL', objectid: 'S-1-5-21-TEST-515', domain: 'TEST.LOCAL'});

MATCH (du:Group {objectid: 'S-1-5-21-TEST-513'}),
      (dc:Group {objectid: 'S-1-5-21-TEST-515'}),
      (agent:CertTemplate {name: 'Agent@TEST.LOCAL'}),
      (victim:CertTemplate {name: 'OnlyComputersVictim@TEST.LOCAL'}),
      (ca:EnterpriseCA {caname: 'TEST-CA-3'})
CREATE (du)-[:Enroll]->(agent)
CREATE (dc)-[:Enroll]->(victim)
CREATE (agent)-[:PublishedTo]->(ca)
CREATE (victim)-[:PublishedTo]->(ca);
