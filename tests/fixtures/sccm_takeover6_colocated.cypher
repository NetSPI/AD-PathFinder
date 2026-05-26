// TAKEOVER-6 negative: SMS Provider and SMS Site Server roles are on the
// SAME host (small-deployment co-location). TAKEOVER-6 assumes the site
// server's machine account is local admin on a separate SMS Provider, so
// co-location removes the relay primitive. The check must NOT fire.

CREATE (u:User {name: 'alice@TEST.LOCAL', objectid: 'S-1-5-21-TEST-1101', enabled: true, domain: 'TEST.LOCAL'});

CREATE (site:SCCM_Site {siteCode: 'P02', sourceForest: 'TEST.LOCAL'});

CREATE (combined:Computer {
  name: 'ALLINONE.TEST.LOCAL',
  DNSHostName: 'allinone.test.local',
  samaccountname: 'ALLINONE$',
  objectid: 'S-1-5-21-TEST-1210',
  enabled: true,
  domain: 'TEST.LOCAL',
  SMBSigningRequired: false,
  SCCMSiteSystemRoles: ['SMS Provider@P02', 'SMS Site Server@P02']
});

CREATE (relay:Group {name: 'AUTHENTICATED USERS@TEST.LOCAL', objectid: 'S-1-5-11', domain: 'TEST.LOCAL'});

MATCH (relay:Group {objectid: 'S-1-5-11'}),
      (combined:Computer {objectid: 'S-1-5-21-TEST-1210'}),
      (site:SCCM_Site {siteCode: 'P02'})
CREATE (relay)-[:CoerceAndRelayToSMB]->(combined)
CREATE (combined)-[:SCCM_AssignAllPermissions]->(site);
