// Cross-domain: two domains with a trust relationship.
// SID filtering disabled to trigger the risk annotation.

CREATE (d1:Domain {name: 'TEST.LOCAL', objectid: 'S-1-5-21-TEST-0'});
CREATE (d2:Domain {name: 'OTHER.LOCAL', objectid: 'S-1-5-21-OTHER-0'});

MATCH (d1:Domain {name: 'TEST.LOCAL'}),
      (d2:Domain {name: 'OTHER.LOCAL'})
CREATE (d1)-[:TrustedBy {trusttype: 'ParentChild', transitive: true, sidfilteringenabled: false}]->(d2);
