// Tier E positive: two enabled computers. Weak-password signal comes
// from the fake AccountAnalysis the test injects.

CREATE (c1:Computer {
  name: 'WS01.TEST.LOCAL',
  DNSHostName: 'ws01.test.local',
  samaccountname: 'WS01$',
  objectid: 'S-1-5-21-TEST-2100',
  enabled: true,
  domain: 'TEST.LOCAL',
  operatingsystem: 'Windows 10 Enterprise'
});

CREATE (c2:Computer {
  name: 'WS02.TEST.LOCAL',
  DNSHostName: 'ws02.test.local',
  samaccountname: 'WS02$',
  objectid: 'S-1-5-21-TEST-2101',
  enabled: true,
  domain: 'TEST.LOCAL',
  operatingsystem: 'Windows 11 Enterprise'
});
