// ESC3 victim positive: paired with an agent template on the same CA, so the
// chain is complete. Three templates published on TEST-CA:
//   - Agent: Cert Request Agent EKU, low-priv enrol (ESC3.1)
//   - VictimV1: schema v1, auth-enabled, low-priv enrol (legacy co-sign path)
//   - VictimCoSign: schema v2, auth-enabled, authorized_signatures=1, has
//     Cert Request Agent in applicationpolicies (modern co-sign path)
//   - NotVictim: auth-enabled but schema v2 with no co-sign requirement —
//     must NOT fire.

CREATE (u:User {name: 'alice@TEST.LOCAL', objectid: 'S-1-5-21-TEST-1300', enabled: true, domain: 'TEST.LOCAL'});

CREATE (agent:CertTemplate {
  name: 'Agent@TEST.LOCAL',
  effectiveekus: ['1.3.6.1.4.1.311.20.2.1'],
  authenticationenabled: false,
  requiresmanagerapproval: false,
  authorizedsignatures: 0,
  schemaversion: 2
});

CREATE (vV1:CertTemplate {
  name: 'VictimV1@TEST.LOCAL',
  authenticationenabled: true,
  requiresmanagerapproval: false,
  authorizedsignatures: 0,
  schemaversion: 1
});

CREATE (vCoSign:CertTemplate {
  name: 'VictimCoSign@TEST.LOCAL',
  authenticationenabled: true,
  requiresmanagerapproval: false,
  authorizedsignatures: 1,
  schemaversion: 2,
  applicationpolicies: ['1.3.6.1.4.1.311.20.2.1']
});

CREATE (notV:CertTemplate {
  name: 'NotVictim@TEST.LOCAL',
  authenticationenabled: true,
  requiresmanagerapproval: false,
  authorizedsignatures: 0,
  schemaversion: 2
});

CREATE (ca:EnterpriseCA {caname: 'TEST-CA', dnshostname: 'ca.test.local'});

CREATE (g:Group {name: 'DOMAIN USERS@TEST.LOCAL', objectid: 'S-1-5-21-TEST-513', domain: 'TEST.LOCAL'});

MATCH (g:Group {objectid: 'S-1-5-21-TEST-513'}),
      (agent:CertTemplate {name: 'Agent@TEST.LOCAL'}),
      (vV1:CertTemplate {name: 'VictimV1@TEST.LOCAL'}),
      (vCoSign:CertTemplate {name: 'VictimCoSign@TEST.LOCAL'}),
      (notV:CertTemplate {name: 'NotVictim@TEST.LOCAL'}),
      (ca:EnterpriseCA {caname: 'TEST-CA'})
CREATE (g)-[:Enroll]->(agent)
CREATE (g)-[:Enroll]->(vV1)
CREATE (g)-[:Enroll]->(vCoSign)
CREATE (g)-[:Enroll]->(notV)
CREATE (agent)-[:PublishedTo]->(ca)
CREATE (vV1)-[:PublishedTo]->(ca)
CREATE (vCoSign)-[:PublishedTo]->(ca)
CREATE (notV)-[:PublishedTo]->(ca);
