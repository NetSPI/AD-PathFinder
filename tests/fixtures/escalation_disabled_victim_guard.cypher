CREATE (:User {name: 'ATT-NONWRITE-DISABLED@TEST.LOCAL', objectid: 'S-1-5-21-TEST-90011', enabled: true, domain: 'TEST.LOCAL'});
CREATE (:User {name: 'VIC-DISABLED-A@TEST.LOCAL', objectid: 'S-1-5-21-TEST-90001', enabled: false, highvalue: true, system_tags: 'admin_tier_0', domain: 'TEST.LOCAL'});
CREATE (:User {name: 'ATT-WRITE-DISABLED@TEST.LOCAL', objectid: 'S-1-5-21-TEST-90012', enabled: true, domain: 'TEST.LOCAL'});
CREATE (:User {name: 'VIC-DISABLED-B@TEST.LOCAL', objectid: 'S-1-5-21-TEST-90002', enabled: false, highvalue: true, system_tags: 'admin_tier_0', domain: 'TEST.LOCAL'});
CREATE (:User {name: 'ATT-NONWRITE-ENABLED@TEST.LOCAL', objectid: 'S-1-5-21-TEST-90013', enabled: true, domain: 'TEST.LOCAL'});
CREATE (:User {name: 'VIC-ENABLED@TEST.LOCAL', objectid: 'S-1-5-21-TEST-90003', enabled: true, highvalue: true, system_tags: 'admin_tier_0', domain: 'TEST.LOCAL'});
CREATE (:User {name: 'ATT-BOTH-DISABLED@TEST.LOCAL', objectid: 'S-1-5-21-TEST-90014', enabled: true, domain: 'TEST.LOCAL'});
CREATE (:User {name: 'VIC-DISABLED-C@TEST.LOCAL', objectid: 'S-1-5-21-TEST-90004', enabled: false, highvalue: true, system_tags: 'admin_tier_0', domain: 'TEST.LOCAL'});
CREATE (:User {name: 'ATT-WRITEACCTRES-DISABLED@TEST.LOCAL', objectid: 'S-1-5-21-TEST-90015', enabled: true, domain: 'TEST.LOCAL'});
CREATE (:User {name: 'VIC-DISABLED-D@TEST.LOCAL', objectid: 'S-1-5-21-TEST-90005', enabled: false, highvalue: true, system_tags: 'admin_tier_0', domain: 'TEST.LOCAL'});

MATCH (a {objectid: 'S-1-5-21-TEST-90011'}), (v {objectid: 'S-1-5-21-TEST-90001'}) CREATE (a)-[:AllExtendedRights]->(v);
MATCH (a {objectid: 'S-1-5-21-TEST-90012'}), (v {objectid: 'S-1-5-21-TEST-90002'}) CREATE (a)-[:GenericWrite]->(v);
MATCH (a {objectid: 'S-1-5-21-TEST-90013'}), (v {objectid: 'S-1-5-21-TEST-90003'}) CREATE (a)-[:AllExtendedRights]->(v);
MATCH (a {objectid: 'S-1-5-21-TEST-90014'}), (v {objectid: 'S-1-5-21-TEST-90004'}) CREATE (a)-[:AllExtendedRights]->(v);
MATCH (a {objectid: 'S-1-5-21-TEST-90014'}), (v {objectid: 'S-1-5-21-TEST-90004'}) CREATE (a)-[:GenericWrite]->(v);
MATCH (a {objectid: 'S-1-5-21-TEST-90015'}), (v {objectid: 'S-1-5-21-TEST-90005'}) CREATE (a)-[:WriteAccountRestrictions]->(v);
