// SCCM anonymous policy retrieval positive: Computer with SMS Management Point role.

CREATE (site:SCCM_Site {siteCode: 'P01', sourceForest: 'TEST.LOCAL'});

CREATE (mp:Computer {
  name: 'MGMTPT.TEST.LOCAL',
  DNSHostName: 'mgmtpt.test.local',
  samaccountname: 'MGMTPT$',
  objectid: 'S-1-5-21-TEST-1300',
  enabled: true,
  domain: 'TEST.LOCAL',
  SCCMSiteSystemRoles: ['SMS Management Point@P01'],
  SCCMClientCertificateRequired: false,
  collectionSource: ['HTTP-MPKEYINFORMATION']
});
