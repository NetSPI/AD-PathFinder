// TAKEOVER-4 positive: CAS hierarchy with child site server SMB signing disabled.

CREATE (parent_site:SCCM_Site {siteCode: 'CAS', sourceForest: 'TEST.LOCAL'});
CREATE (child_site:SCCM_Site {siteCode: 'P01', sourceForest: 'TEST.LOCAL', parentSiteCode: 'CAS'});

MATCH (parent_site:SCCM_Site {siteCode: 'CAS'}), (child_site:SCCM_Site {siteCode: 'P01'})
CREATE (parent_site)-[:SCCM_AdminsReplicatedTo]->(child_site);

CREATE (cas_comp:Computer {
  name: 'CASSERVER.TEST.LOCAL',
  DNSHostName: 'casserver.test.local',
  samaccountname: 'CASSERVER$',
  objectid: 'S-1-5-21-TEST-1500',
  enabled: true,
  domain: 'TEST.LOCAL',
  SMBSigningRequired: true,
  SCCMSiteSystemRoles: ['SMS Site Server@CAS']
});

CREATE (child_comp:Computer {
  name: 'CHILDSERVER.TEST.LOCAL',
  DNSHostName: 'childserver.test.local',
  samaccountname: 'CHILDSERVER$',
  objectid: 'S-1-5-21-TEST-1501',
  enabled: true,
  domain: 'TEST.LOCAL',
  SMBSigningRequired: false,
  SCCMSiteSystemRoles: ['SMS Site Server@P01']
});
