// Positive: a Windows Server 2025 DC exists, and a well-known default group
// (Domain Users) has GenericAll on an OU — the BadSuccessor primitive.

CREATE (dc:Computer {
  name: 'DC2025.TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-4101',
  samaccountname: 'DC2025$',
  enabled: true,
  domain: 'TEST.LOCAL',
  operatingsystem: 'Windows Server 2025'
});

CREATE (dcGroup:Group {
  name: 'DOMAIN CONTROLLERS@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-516',
  domain: 'TEST.LOCAL'
});

CREATE (ou:OU {
  name: 'WORKSTATIONS',
  objectid: 'S-1-5-21-TEST-OU-1'
});

// Domain Users needs the Base label for the OU privilege query.
// Realistic numeric SID required — bad_successor.py:57 checks the character
// before the RID suffix is a digit or '-', so S-1-5-21-TEST-513 fails.
CREATE (g:Group:Base {
  name: 'DOMAIN USERS@TEST.LOCAL',
  objectid: 'S-1-5-21-1111111111-2222222222-3333333333-513',
  domain: 'TEST.LOCAL'
});

// DC is member of Domain Controllers
MATCH (dc:Computer {objectid: 'S-1-5-21-TEST-4101'}),
      (dcGroup:Group {objectid: 'S-1-5-21-TEST-516'})
CREATE (dc)-[:MemberOf]->(dcGroup);

// Domain Users has GenericAll on the OU
MATCH (ou:OU {objectid: 'S-1-5-21-TEST-OU-1'}),
      (g:Group {objectid: 'S-1-5-21-1111111111-2222222222-3333333333-513'})
CREATE (ou)<-[:GenericAll]-(g);
