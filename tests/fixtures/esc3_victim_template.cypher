// ESC3 victim positive: two templates qualify per Certipy criteria.
// - VictimV1: schema v1, auth-enabled, low-priv enrol (legacy co-sign path)
// - VictimCoSign: schema v2, auth-enabled, requires 1 signature with the
//   Cert Request Agent application policy (modern co-sign path)
// A third template (NotVictim) is auth-enabled but schema v2 with no
// co-sign requirement — must NOT fire.

CREATE (u:User {name: 'alice@TEST.LOCAL', objectid: 'S-1-5-21-TEST-1300', enabled: true, domain: 'TEST.LOCAL'});

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
      (vV1:CertTemplate {name: 'VictimV1@TEST.LOCAL'}),
      (vCoSign:CertTemplate {name: 'VictimCoSign@TEST.LOCAL'}),
      (notV:CertTemplate {name: 'NotVictim@TEST.LOCAL'}),
      (ca:EnterpriseCA {caname: 'TEST-CA'})
CREATE (g)-[:Enroll]->(vV1)
CREATE (g)-[:Enroll]->(vCoSign)
CREATE (g)-[:Enroll]->(notV)
CREATE (vV1)-[:PublishedTo]->(ca)
CREATE (vCoSign)-[:PublishedTo]->(ca)
CREATE (notV)-[:PublishedTo]->(ca);
