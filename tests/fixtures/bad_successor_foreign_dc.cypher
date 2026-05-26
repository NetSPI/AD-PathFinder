// BadSuccessor negative: a foreign Windows Server 2025 DC must not open the
// gate for vulnerable OU/container ACLs in TEST.LOCAL.

CREATE (otherDc:Computer:Base {
  name: 'DC2025.OTHER.LOCAL',
  objectid: 'S-1-5-21-OTHER-4101',
  samaccountname: 'DC2025$',
  enabled: true,
  domain: 'OTHER.LOCAL',
  operatingsystem: 'Windows Server 2025 Standard'
});

CREATE (otherDcGroup:Group:Base {
  name: 'DOMAIN CONTROLLERS@OTHER.LOCAL',
  objectid: 'S-1-5-21-OTHER-516',
  domain: 'OTHER.LOCAL'
});

CREATE (testOu:OU:Base {
  name: 'TEST ONLY OU@TEST.LOCAL',
  objectid: 'TEST-OU-FOREIGN-DC-GATE',
  domain: 'TEST.LOCAL'
});

CREATE (testHelpdesk:Group:Base {
  name: 'TEST HELPDESK@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-1701',
  domain: 'TEST.LOCAL'
});

MATCH (otherDc:Computer {objectid: 'S-1-5-21-OTHER-4101'}),
      (otherDcGroup:Group {objectid: 'S-1-5-21-OTHER-516'})
CREATE (otherDc)-[:MemberOf]->(otherDcGroup);

MATCH (testHelpdesk:Group {objectid: 'S-1-5-21-TEST-1701'}),
      (testOu:OU {objectid: 'TEST-OU-FOREIGN-DC-GATE'})
CREATE (testHelpdesk)-[:GenericAll]->(testOu);
