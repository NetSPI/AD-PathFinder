// ESC8 positive: Enterprise CA with a vulnerable HTTP enrollment endpoint.

CREATE (ca:EnterpriseCA {
  caname: 'TEST-CA',
  dnshostname: 'ca.test.local',
  hasvulnerableendpoint: true
});
