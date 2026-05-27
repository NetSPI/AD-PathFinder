// Positive: Domain Users has CoerceAndRelayToAdminService to an SCCM_Site
// node. SCCM_Site nodes have no .name property — only .displayName and
// .siteCode. The query must coalesce on those, and the normaliser must
// preserve the "SCCM Site" type, otherwise the row is silently dropped.

CREATE (g:Group {
  name: 'DOMAIN USERS@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-513',
  domain: 'TEST.LOCAL'
});

CREATE (site:SCCM_Site {
  objectid: 'P02',
  siteCode: 'P02',
  displayName: 'Lab Primary Site',
  sourceForest: 'TEST.LOCAL'
});

MATCH (g:Group {objectid: 'S-1-5-21-TEST-513'}),
      (site:SCCM_Site {objectid: 'P02'})
CREATE (g)-[:CoerceAndRelayToAdminService]->(site);
