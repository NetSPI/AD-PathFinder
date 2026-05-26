// Tier D positive: two enabled computers, but only the one present in the
// escalation-path cache should appear in findings.

CREATE (c1:Computer {
  name: 'WS01.TEST.LOCAL',
  DNSHostName: 'ws01.test.local',
  samaccountname: 'WS01$',
  objectid: 'S-1-5-21-TEST-1500',
  enabled: true,
  domain: 'TEST.LOCAL',
  operatingsystem: 'Windows 10 Enterprise'
});

CREATE (c2:Computer {
  name: 'WS02.TEST.LOCAL',
  DNSHostName: 'ws02.test.local',
  samaccountname: 'WS02$',
  objectid: 'S-1-5-21-TEST-1501',
  enabled: true,
  domain: 'TEST.LOCAL',
  operatingsystem: 'Windows 11 Enterprise'
});
