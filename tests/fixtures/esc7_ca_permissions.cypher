// ESC7 positive: low-priv group has ManageCA on an Enterprise CA.

CREATE (u:User {name: 'alice@TEST.LOCAL', objectid: 'S-1-5-21-TEST-1100', enabled: true, domain: 'TEST.LOCAL'});

CREATE (ca:EnterpriseCA {caname: 'TEST-CA', dnshostname: 'ca.test.local'});

CREATE (g:Group {name: 'DOMAIN USERS@TEST.LOCAL', objectid: 'S-1-5-21-TEST-513', domain: 'TEST.LOCAL'});

MATCH (g:Group {objectid: 'S-1-5-21-TEST-513'}),
      (ca:EnterpriseCA {caname: 'TEST-CA'})
CREATE (g)-[:ManageCA]->(ca);
