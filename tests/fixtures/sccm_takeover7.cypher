// TAKEOVER-7 positive: 2+ site servers for same site, one with SMB signing disabled.

CREATE (site:SCCM_Site {siteCode: 'P01', sourceForest: 'TEST.LOCAL'});

CREATE (srv1:Computer {
  name: 'SITESVR1.TEST.LOCAL',
  DNSHostName: 'sitesvr1.test.local',
  samaccountname: 'SITESVR1$',
  objectid: 'S-1-5-21-TEST-1600',
  enabled: true,
  domain: 'TEST.LOCAL',
  SMBSigningRequired: true,
  SCCMSiteSystemRoles: ['SMS Site Server@P01']
});

CREATE (srv2:Computer {
  name: 'SITESVR2.TEST.LOCAL',
  DNSHostName: 'sitesvr2.test.local',
  samaccountname: 'SITESVR2$',
  objectid: 'S-1-5-21-TEST-1601',
  enabled: true,
  domain: 'TEST.LOCAL',
  SMBSigningRequired: false,
  SCCMSiteSystemRoles: ['SMS Site Server@P01']
});
