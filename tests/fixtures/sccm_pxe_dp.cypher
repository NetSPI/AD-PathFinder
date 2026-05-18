// SCCM PXE Distribution Point positive: Computer with Distribution Point role.

CREATE (site:SCCM_Site {siteCode: 'P01', sourceForest: 'TEST.LOCAL'});

CREATE (dp:Computer {
  name: 'DISTPT.TEST.LOCAL',
  DNSHostName: 'distpt.test.local',
  samaccountname: 'DISTPT$',
  objectid: 'S-1-5-21-TEST-1400',
  enabled: true,
  domain: 'TEST.LOCAL',
  SCCMSiteSystemRoles: ['Distribution Point@P01'],
  SCCMIsPXESupportEnabled: true,
  collectionSource: ['SMB-REMINST']
});

CREATE (plainDp:Computer {
  name: 'PLAIN-DP.TEST.LOCAL',
  DNSHostName: 'plain-dp.test.local',
  samaccountname: 'PLAIN-DP$',
  objectid: 'S-1-5-21-TEST-1401',
  enabled: true,
  domain: 'TEST.LOCAL',
  SCCMSiteSystemRoles: ['Distribution Point@P01'],
  SCCMIsPXESupportEnabled: false,
  collectionSource: ['SMB-SMS_DP$']
});
