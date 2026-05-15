// Tier D positive: an enabled computer running the WebClient service. The
// "escalation path" half lives in the shared cache injected by the test, not
// in the graph (has_escalation_path() reads cache, not Cypher).

CREATE (c:Computer {
  name: 'WS01.TEST.LOCAL',
  DNSHostName: 'ws01.test.local',
  samaccountname: 'WS01$',
  objectid: 'S-1-5-21-TEST-1400',
  enabled: true,
  domain: 'TEST.LOCAL',
  webclientrunning: true,
  operatingsystem: 'Windows 10'
});

// Second computer with WebClient running but NO entry in the escalation cache:
// confirms the check filters on cache presence, not just the WebClient flag.
CREATE (c2:Computer {
  name: 'WS02.TEST.LOCAL',
  DNSHostName: 'ws02.test.local',
  samaccountname: 'WS02$',
  objectid: 'S-1-5-21-TEST-1401',
  enabled: true,
  domain: 'TEST.LOCAL',
  webclientrunning: true,
  operatingsystem: 'Windows 11'
});
