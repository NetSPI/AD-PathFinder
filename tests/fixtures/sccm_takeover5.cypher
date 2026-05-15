// TAKEOVER-5 positive: AdminService relay when SMS Provider is on a separate host.

CREATE (site:SCCM_Site {siteCode: 'P01', sourceForest: 'TEST.LOCAL'});

CREATE (ss:Computer {
  name: 'SITESVR.TEST.LOCAL',
  DNSHostName: 'SITESVR.TEST.LOCAL',
  samaccountname: 'SITESVR$',
  objectid: 'S-1-5-21-TEST-1900',
  enabled: true,
  domain: 'TEST.LOCAL',
  SCCMSiteSystemRoles: ['SMS Site Server@P01']
});

CREATE (provider:Computer {
  name: 'PROVIDER.TEST.LOCAL',
  DNSHostName: 'PROVIDER.TEST.LOCAL',
  samaccountname: 'PROVIDER$',
  objectid: 'S-1-5-21-TEST-1901',
  enabled: true,
  domain: 'TEST.LOCAL',
  SCCMSiteSystemRoles: ['SMS Provider@P01']
});

CREATE (g:Group {name: 'AUTHENTICATED USERS@TEST.LOCAL', objectid: 'S-1-5-11', domain: 'TEST.LOCAL'});

MATCH (g:Group {objectid: 'S-1-5-11'}),
      (site:SCCM_Site {siteCode: 'P01'})
CREATE (g)-[:CoerceAndRelayToAdminService]->(site);
