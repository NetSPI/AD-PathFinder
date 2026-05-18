// Positive: computer with SMB signing disabled.

CREATE (c:Computer {
  name: 'WS01.TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-1001',
  samaccountname: 'WS01$',
  enabled: true,
  domain: 'TEST.LOCAL',
  operatingsystem: 'Windows 10 Enterprise',
  smbsigning: false
});
