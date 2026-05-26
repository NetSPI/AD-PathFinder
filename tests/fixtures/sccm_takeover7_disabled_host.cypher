// TAKEOVER-7 negative: one live site server plus one decommissioned (disabled)
// site server for the same site. The disabled host carries a stale
// SCCMSiteSystemRoles value but no longer exists, so it must not count toward
// the 2+ HA-server threshold — the check must return no finding.

CREATE (site:SCCM_Site {siteCode: 'P01', sourceForest: 'TEST.LOCAL'});

CREATE (live:Computer {
  name: 'SITESVR1.TEST.LOCAL',
  DNSHostName: 'sitesvr1.test.local',
  samaccountname: 'SITESVR1$',
  objectid: 'S-1-5-21-TEST-1600',
  enabled: true,
  domain: 'TEST.LOCAL',
  SMBSigningRequired: false,
  SCCMSiteSystemRoles: ['SMS Site Server@P01']
});

CREATE (stale:Computer {
  name: 'OLDSITESVR.TEST.LOCAL',
  DNSHostName: 'oldsitesvr.test.local',
  samaccountname: 'OLDSITESVR$',
  objectid: 'S-1-5-21-TEST-1699',
  enabled: false,
  domain: 'TEST.LOCAL',
  SMBSigningRequired: false,
  SCCMSiteSystemRoles: ['SMS Site Server@P01']
});
