// Positive: krbtgt account with pwdlastset well over 180 days ago.
// Unix timestamp 1706745600 = 2024-02-01T00:00:00Z.
// Deliberately mid-year so no timezone offset can shift the date into 2023.

CREATE (u:User {
  name: 'KRBTGT@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-502',
  samaccountname: 'krbtgt',
  enabled: false,
  domain: 'TEST.LOCAL',
  pwdlastset: 1706745600
});
