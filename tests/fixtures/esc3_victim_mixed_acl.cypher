// ESC3 mixed-ACL positive: the agent has a broad enrolment ACL (Domain
// Users + Authenticated Users) and the victim is computer-only (Domain
// Computers). The chain is exploitable via Authenticated Users (its
// member space covers computers), so the finding must fire — but the
// displayed agent enrollers must NOT include Domain Users, since a
// domain user cannot enrol the computer-only victim and so cannot
// complete the chain.

CREATE (alice:User {name: 'alice@TEST.LOCAL', objectid: 'S-1-5-21-TEST-1330', enabled: true, domain: 'TEST.LOCAL'});

CREATE (agent:CertTemplate {
  name: 'Agent@TEST.LOCAL',
  effectiveekus: ['1.3.6.1.4.1.311.20.2.1'],
  authenticationenabled: false,
  requiresmanagerapproval: false,
  authorizedsignatures: 0,
  schemaversion: 2
});

CREATE (victim:CertTemplate {
  name: 'MachineVictim@TEST.LOCAL',
  authenticationenabled: true,
  requiresmanagerapproval: false,
  authorizedsignatures: 0,
  schemaversion: 1
});

CREATE (ca:EnterpriseCA {caname: 'TEST-CA-4', dnshostname: 'ca4.test.local'});

CREATE (du:Group {name: 'DOMAIN USERS@TEST.LOCAL', objectid: 'S-1-5-21-TEST-513', domain: 'TEST.LOCAL'});
CREATE (au:Group {name: 'AUTHENTICATED USERS@TEST.LOCAL', objectid: 'TEST-S-1-5-11', domain: 'TEST.LOCAL'});
CREATE (dc:Group {name: 'DOMAIN COMPUTERS@TEST.LOCAL', objectid: 'S-1-5-21-TEST-515', domain: 'TEST.LOCAL'});

MATCH (du:Group {objectid: 'S-1-5-21-TEST-513'}),
      (au:Group {objectid: 'TEST-S-1-5-11'}),
      (dc:Group {objectid: 'S-1-5-21-TEST-515'}),
      (agent:CertTemplate {name: 'Agent@TEST.LOCAL'}),
      (victim:CertTemplate {name: 'MachineVictim@TEST.LOCAL'}),
      (ca:EnterpriseCA {caname: 'TEST-CA-4'})
CREATE (du)-[:Enroll]->(agent)
CREATE (au)-[:Enroll]->(agent)
CREATE (dc)-[:Enroll]->(victim)
CREATE (agent)-[:PublishedTo]->(ca)
CREATE (victim)-[:PublishedTo]->(ca);
