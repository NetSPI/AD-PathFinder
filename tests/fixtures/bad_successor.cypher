// BadSuccessor: a Windows Server 2025 DC opens the gate, then the check flags
// every enabled, non-Tier-0 principal with full control over an OU or Container.
// Positives: Domain Users -> OU, Helpdesk -> Container.
// Negatives: a disabled user and a Tier-0 group are excluded.

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

MATCH (dc:Computer {objectid: 'S-1-5-21-TEST-4101'}),
      (dcGroup:Group {objectid: 'S-1-5-21-TEST-516'})
CREATE (dc)-[:MemberOf]->(dcGroup);

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
