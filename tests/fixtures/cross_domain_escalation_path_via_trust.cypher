// Multi-domain: user in CORP.LOCAL reaches Domain Admins in PARTNER.LOCAL
// via a multi-hop cross-domain path: user -> group in CORP -> foreign security
// principal in PARTNER -> nested group -> Domain Admins.
// Exercises multi-hop cross-domain escalation through MemberOf/GenericAll.
// Note: the TrustedBy edge is context only, the check query does not traverse it.

CREATE (d1:Domain {name: 'CORP.LOCAL', objectid: 'S-1-5-21-CORP-0'});
CREATE (d2:Domain {name: 'PARTNER.LOCAL', objectid: 'S-1-5-21-PARTNER-0'});

// Bidirectional trust
MATCH (d1:Domain {name: 'CORP.LOCAL'}),
      (d2:Domain {name: 'PARTNER.LOCAL'})
CREATE (d1)-[:TrustedBy {trusttype: 'External', transitive: false, sidfilteringenabled: false}]->(d2);

// Source user in CORP.LOCAL
CREATE (u:User {
  name: 'SVCACCOUNT@CORP.LOCAL',
  objectid: 'S-1-5-21-CORP-5000',
  enabled: true,
  domain: 'CORP.LOCAL'
});

// Group in CORP.LOCAL that the user belongs to
CREATE (corpGroup:Group {
  name: 'IT-OPS@CORP.LOCAL',
  objectid: 'S-1-5-21-CORP-5001',
  domain: 'CORP.LOCAL'
});

// Foreign security principal representation in PARTNER.LOCAL
// (how BloodHound models cross-domain membership)
CREATE (fsp:Group {
  name: 'S-1-5-21-CORP-5001@PARTNER.LOCAL',
  objectid: 'S-1-5-21-CORP-5001-FSP',
  domain: 'PARTNER.LOCAL'
});

// Intermediate group in PARTNER.LOCAL
CREATE (partnerGroup:Group {
  name: 'SERVER-ADMINS@PARTNER.LOCAL',
  objectid: 'S-1-5-21-PARTNER-6001',
  domain: 'PARTNER.LOCAL'
});

// Domain Admins in PARTNER.LOCAL
CREATE (da:Group {
  name: 'DOMAIN ADMINS@PARTNER.LOCAL',
  objectid: 'S-1-5-21-PARTNER-512',
  domain: 'PARTNER.LOCAL'
});

// Build the chain: user -> corpGroup -> fsp -> partnerGroup -> DA
MATCH (u:User {objectid: 'S-1-5-21-CORP-5000'}),
      (g:Group {objectid: 'S-1-5-21-CORP-5001'})
CREATE (u)-[:MemberOf]->(g);

MATCH (corpGroup:Group {objectid: 'S-1-5-21-CORP-5001'}),
      (fsp:Group {objectid: 'S-1-5-21-CORP-5001-FSP'})
CREATE (corpGroup)-[:MemberOf]->(fsp);

MATCH (fsp:Group {objectid: 'S-1-5-21-CORP-5001-FSP'}),
      (partnerGroup:Group {objectid: 'S-1-5-21-PARTNER-6001'})
CREATE (fsp)-[:MemberOf]->(partnerGroup);

MATCH (partnerGroup:Group {objectid: 'S-1-5-21-PARTNER-6001'}),
      (da:Group {objectid: 'S-1-5-21-PARTNER-512'})
CREATE (partnerGroup)-[:GenericAll]->(da);
