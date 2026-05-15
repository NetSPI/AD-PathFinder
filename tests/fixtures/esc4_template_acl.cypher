// ESC4 positive: low-priv group has write permissions on a published template.

CREATE (u:User {name: 'alice@TEST.LOCAL', objectid: 'S-1-5-21-TEST-1100', enabled: true, domain: 'TEST.LOCAL'});

CREATE (t:CertTemplate {name: 'WritableTemplate@TEST.LOCAL'});

CREATE (ca:EnterpriseCA {caname: 'TEST-CA', dnshostname: 'ca.test.local'});

CREATE (g:Group {name: 'DOMAIN USERS@TEST.LOCAL', objectid: 'S-1-5-21-TEST-513', domain: 'TEST.LOCAL'});

MATCH (g:Group {objectid: 'S-1-5-21-TEST-513'}),
      (t:CertTemplate {name: 'WritableTemplate@TEST.LOCAL'}),
      (ca:EnterpriseCA {caname: 'TEST-CA'})
CREATE (g)-[:GenericAll]->(t)
CREATE (t)-[:PublishedTo]->(ca);
