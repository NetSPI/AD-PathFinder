// Multi-domain: computer in CORP.LOCAL reaches Domain Admins in PARTNER.LOCAL
// via a multi-hop cross-domain path: computer -> AdminTo a server in
// PARTNER.LOCAL -> MemberOf group -> GenericAll on Domain Admins.
// Exercises cross-domain computer escalation through AdminTo/MemberOf/GenericAll.
// Note: the TrustedBy edge is context only, the check query does not traverse it.

CREATE (d1:Domain {name: 'CORP.LOCAL', objectid: 'S-1-5-21-CORP-0'});
CREATE (d2:Domain {name: 'PARTNER.LOCAL', objectid: 'S-1-5-21-PARTNER-0'});

MATCH (d1:Domain {name: 'CORP.LOCAL'}),
      (d2:Domain {name: 'PARTNER.LOCAL'})
CREATE (d1)-[:TrustedBy {trusttype: 'External', transitive: false, sidfilteringenabled: false}]->(d2);

// Source computer in CORP.LOCAL (non-tier-0)
CREATE (c:Computer {
  name: 'JUMPBOX.CORP.LOCAL',
  DNSHostName: 'jumpbox.corp.local',
  samaccountname: 'JUMPBOX$',
  objectid: 'S-1-5-21-CORP-7000',
  enabled: true,
  domain: 'CORP.LOCAL'
});

// Server in PARTNER.LOCAL that the computer has AdminTo
CREATE (srv:Computer {
  name: 'DBSRV.PARTNER.LOCAL',
  DNSHostName: 'dbsrv.partner.local',
  samaccountname: 'DBSRV$',
  objectid: 'S-1-5-21-PARTNER-7001',
  enabled: true,
  domain: 'PARTNER.LOCAL'
});

// Intermediate group in PARTNER.LOCAL with path to DA
CREATE (srvAdmins:Group {
  name: 'DB-ADMINS@PARTNER.LOCAL',
  objectid: 'S-1-5-21-PARTNER-7002',
  domain: 'PARTNER.LOCAL'
});

// Domain Admins in PARTNER.LOCAL
CREATE (da:Group {
  name: 'DOMAIN ADMINS@PARTNER.LOCAL',
  objectid: 'S-1-5-21-PARTNER-512',
  domain: 'PARTNER.LOCAL'
});

// Build the chain: computer -AdminTo-> server -MemberOf-> group -GenericAll-> DA
MATCH (c:Computer {objectid: 'S-1-5-21-CORP-7000'}),
      (srv:Computer {objectid: 'S-1-5-21-PARTNER-7001'})
CREATE (c)-[:AdminTo]->(srv);

MATCH (srv:Computer {objectid: 'S-1-5-21-PARTNER-7001'}),
      (g:Group {objectid: 'S-1-5-21-PARTNER-7002'})
CREATE (srv)-[:MemberOf]->(g);

MATCH (g:Group {objectid: 'S-1-5-21-PARTNER-7002'}),
      (da:Group {objectid: 'S-1-5-21-PARTNER-512'})
CREATE (g)-[:GenericAll]->(da);
