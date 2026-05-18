// ELEVATE-1 positive: SMB relay from site server to non-site-server SCCM role holder.

CREATE (site:SCCM_Site {siteCode: 'P01', sourceForest: 'TEST.LOCAL'});

CREATE (target:Computer {
  name: 'SQLSVR.TEST.LOCAL',
  DNSHostName: 'sqlsvr.test.local',
  samaccountname: 'SQLSVR$',
  objectid: 'S-1-5-21-TEST-2100',
  enabled: true,
  domain: 'TEST.LOCAL',
  SMBSigningRequired: false,
  SCCMSiteSystemRoles: ['SMS SQL Server@P01']
});

CREATE (ss:Computer {
  name: 'SITESVR.TEST.LOCAL',
  DNSHostName: 'sitesvr.test.local',
  samaccountname: 'SITESVR$',
  objectid: 'S-1-5-21-TEST-2101',
  enabled: true,
  domain: 'TEST.LOCAL',
  SCCMSiteSystemRoles: ['SMS Site Server@P01']
});

CREATE (g:Group {name: 'AUTHENTICATED USERS@TEST.LOCAL', objectid: 'S-1-5-11', domain: 'TEST.LOCAL'});

MATCH (g:Group {objectid: 'S-1-5-11'}),
      (target:Computer {objectid: 'S-1-5-21-TEST-2100'})
CREATE (g)-[:CoerceAndRelayToSMB]->(target);
