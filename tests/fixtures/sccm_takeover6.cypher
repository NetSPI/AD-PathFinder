// SCCM TAKEOVER-6 positive: coerce-and-relay path from any principal to a
// Computer that hosts the SMS Provider role and runs without SMB signing.

CREATE (u:User {name: 'alice@TEST.LOCAL', objectid: 'S-1-5-21-TEST-1100', enabled: true, domain: 'TEST.LOCAL'});

CREATE (site:SCCM_Site {siteCode: 'P01', sourceForest: 'TEST.LOCAL'});

CREATE (provider:Computer {
  name: 'PROVIDER.TEST.LOCAL',
  DNSHostName: 'provider.test.local',
  samaccountname: 'PROVIDER$',
  objectid: 'S-1-5-21-TEST-1200',
  enabled: true,
  domain: 'TEST.LOCAL',
  SMBSigningRequired: false,
  SCCMSiteSystemRoles: ['SMS Provider@P01']
});

CREATE (siteserver:Computer {
  name: 'SITESERVER.TEST.LOCAL',
  DNSHostName: 'siteserver.test.local',
  samaccountname: 'SITESERVER$',
  objectid: 'S-1-5-21-TEST-1201',
  enabled: true,
  domain: 'TEST.LOCAL',
  SMBSigningRequired: true,
  SCCMSiteSystemRoles: ['SMS Site Server@P01']
});

CREATE (relay:Group {name: 'AUTHENTICATED USERS@TEST.LOCAL', objectid: 'S-1-5-11', domain: 'TEST.LOCAL'});

MATCH (relay:Group {objectid: 'S-1-5-11'}),
      (provider:Computer {objectid: 'S-1-5-21-TEST-1200'}),
      (site:SCCM_Site {siteCode: 'P01'})
CREATE (relay)-[:CoerceAndRelayToSMB]->(provider)
CREATE (provider)-[:SCCM_AssignAllPermissions]->(site);
