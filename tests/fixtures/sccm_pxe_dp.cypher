// SCCM PXE Distribution Point positive: Computer with Distribution Point role.

CREATE (site:SCCM_Site {siteCode: 'P01', sourceForest: 'TEST.LOCAL'});

CREATE (dp:Computer {
  name: 'DISTPT.TEST.LOCAL',
  DNSHostName: 'distpt.test.local',
  samaccountname: 'DISTPT$',
  objectid: 'S-1-5-21-TEST-1400',
  enabled: true,
  domain: 'TEST.LOCAL',
  SCCMSiteSystemRoles: ['Distribution Point@P01']
});
