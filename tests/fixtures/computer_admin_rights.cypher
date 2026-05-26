// Positive: one enabled computer has AdminTo another enabled computer.

CREATE (c1:Computer {
  name: 'WS01.TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-5001',
  samaccountname: 'WS01$',
  enabled: true,
  domain: 'TEST.LOCAL'
});

CREATE (c2:Computer {
  name: 'SRV01.TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-5002',
  samaccountname: 'SRV01$',
  enabled: true,
  domain: 'TEST.LOCAL'
});

MATCH (c1:Computer {objectid: 'S-1-5-21-TEST-5001'}),
      (c2:Computer {objectid: 'S-1-5-21-TEST-5002'})
CREATE (c1)-[:AdminTo]->(c2);
