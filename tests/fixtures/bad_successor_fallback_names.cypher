// BadSuccessor regression: missing names should fall back to objectid and
// distinct nameless principals should not collapse into one finding.

CREATE (dc:Computer:Base {
  name: 'DC2025.TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-4101',
  samaccountname: 'DC2025$',
  enabled: true,
  domain: 'TEST.LOCAL',
  operatingsystem: 'Windows Server 2025 Standard'
});

CREATE (dcGroup:Group:Base {
  name: 'DOMAIN CONTROLLERS@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-516',
  domain: 'TEST.LOCAL'
});

CREATE (ou:OU:Base {
  name: 'WORKSTATIONS@TEST.LOCAL',
  objectid: 'TEST-OU-WORKSTATIONS',
  domain: 'TEST.LOCAL'
});

CREATE (namelessOu:OU:Base {
  objectid: 'TEST-OU-NONAME',
  domain: 'TEST.LOCAL'
});

CREATE (u1:User:Base {
  objectid: 'S-1-5-21-TEST-2001',
  domain: 'TEST.LOCAL',
  enabled: true
});

CREATE (u2:User:Base {
  objectid: 'S-1-5-21-TEST-2002',
  domain: 'TEST.LOCAL',
  enabled: true
});

CREATE (named:User:Base {
  name: 'NAMED@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-2003',
  domain: 'TEST.LOCAL',
  enabled: true
});

MATCH (dc:Computer {objectid: 'S-1-5-21-TEST-4101'}),
      (dcGroup:Group {objectid: 'S-1-5-21-TEST-516'})
CREATE (dc)-[:MemberOf]->(dcGroup);

MATCH (u1:User {objectid: 'S-1-5-21-TEST-2001'}),
      (ou:OU {objectid: 'TEST-OU-WORKSTATIONS'})
CREATE (u1)-[:GenericAll]->(ou);

MATCH (u2:User {objectid: 'S-1-5-21-TEST-2002'}),
      (ou:OU {objectid: 'TEST-OU-WORKSTATIONS'})
CREATE (u2)-[:GenericAll]->(ou);

MATCH (named:User {objectid: 'S-1-5-21-TEST-2003'}),
      (namelessOu:OU {objectid: 'TEST-OU-NONAME'})
CREATE (named)-[:GenericAll]->(namelessOu);
