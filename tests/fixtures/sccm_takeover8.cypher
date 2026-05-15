// TAKEOVER-8 positive: HTTP-to-LDAP relay via WebClient-enabled SCCM role holder to misconfigured DC.

CREATE (site:SCCM_Site {siteCode: 'P01', sourceForest: 'TEST.LOCAL'});

CREATE (dom:Domain {name: 'TEST.LOCAL', objectid: 'S-1-5-21-TEST-0'});

CREATE (dc:Computer {
  name: 'DC01.TEST.LOCAL',
  DNSHostName: 'dc01.test.local',
  samaccountname: 'DC01$',
  objectid: 'S-1-5-21-TEST-2000',
  enabled: true,
  domain: 'TEST.LOCAL',
  ldapavailable: true,
  ldapsigning: false,
  ldapsavailable: false,
  ldapsepa: true
});

CREATE (src:Computer {
  name: 'SITESVR.TEST.LOCAL',
  DNSHostName: 'sitesvr.test.local',
  samaccountname: 'SITESVR$',
  objectid: 'S-1-5-21-TEST-2001',
  enabled: true,
  domain: 'TEST.LOCAL',
  webclientrunning: true,
  WebClientRunning: true,
  SCCMSiteSystemRoles: ['SMS Site Server@P01']
});

MATCH (dc:Computer {objectid: 'S-1-5-21-TEST-2000'}),
      (dom:Domain {name: 'TEST.LOCAL'})
CREATE (dc)-[:DCFor]->(dom);
