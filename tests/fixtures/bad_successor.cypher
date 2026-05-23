// BadSuccessor: a Windows Server 2025 DC opens the gate, then the check flags
// every enabled, non-Tier-0 principal with full control over an OU or Container.
// Positives: Domain Users -> OU, Helpdesk -> Container.
// Negatives: a disabled user, a Tier-0 group, and a different-domain OU are excluded.

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

CREATE (ou:OU:Base {
  name: 'WORKSTATIONS@TEST.LOCAL',
  objectid: 'TEST-OU-WORKSTATIONS',
  domain: 'TEST.LOCAL'
});

CREATE (msa:Container:Base {
  name: 'MANAGED SERVICE ACCOUNTS@TEST.LOCAL',
  objectid: 'TEST-CN-MSA',
  domain: 'TEST.LOCAL'
});

CREATE (du:Group:Base {
  name: 'DOMAIN USERS@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-513',
  domain: 'TEST.LOCAL'
});

CREATE (helpdesk:Group:Base {
  name: 'HELPDESK@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-1601',
  domain: 'TEST.LOCAL'
});

CREATE (stale:User:Base {
  name: 'STALE.OPERATOR@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-1602',
  domain: 'TEST.LOCAL',
  enabled: false
});

CREATE (da:Group:Base:Tag_Tier_Zero {
  name: 'DOMAIN ADMINS@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-512',
  domain: 'TEST.LOCAL'
});

CREATE (otherOu:OU:Base {
  name: 'OTHER WORKSTATIONS@OTHER.LOCAL',
  objectid: 'OTHER-OU-WORKSTATIONS',
  domain: 'OTHER.LOCAL'
});

CREATE (otherHelpdesk:Group:Base {
  name: 'OTHER HELPDESK@OTHER.LOCAL',
  objectid: 'S-1-5-21-OTHER-1601',
  domain: 'OTHER.LOCAL'
});

MATCH (dc:Computer {objectid: 'S-1-5-21-TEST-4101'}),
      (dcGroup:Group {objectid: 'S-1-5-21-TEST-516'})
CREATE (dc)-[:MemberOf]->(dcGroup);

MATCH (otherDc:Computer {objectid: 'S-1-5-21-OTHER-4101'}),
      (otherDcGroup:Group {objectid: 'S-1-5-21-OTHER-516'})
CREATE (otherDc)-[:MemberOf]->(otherDcGroup);

MATCH (du:Group {objectid: 'S-1-5-21-TEST-513'}),
      (ou:OU {objectid: 'TEST-OU-WORKSTATIONS'})
CREATE (du)-[:GenericAll]->(ou);

MATCH (helpdesk:Group {objectid: 'S-1-5-21-TEST-1601'}),
      (msa:Container {objectid: 'TEST-CN-MSA'})
CREATE (helpdesk)-[:WriteDacl]->(msa);

MATCH (stale:User {objectid: 'S-1-5-21-TEST-1602'}),
      (ou:OU {objectid: 'TEST-OU-WORKSTATIONS'})
CREATE (stale)-[:GenericAll]->(ou);

MATCH (da:Group {objectid: 'S-1-5-21-TEST-512'}),
      (ou:OU {objectid: 'TEST-OU-WORKSTATIONS'})
CREATE (da)-[:GenericAll]->(ou);

MATCH (otherHelpdesk:Group {objectid: 'S-1-5-21-OTHER-1601'}),
      (otherOu:OU {objectid: 'OTHER-OU-WORKSTATIONS'})
CREATE (otherHelpdesk)-[:GenericAll]->(otherOu);
