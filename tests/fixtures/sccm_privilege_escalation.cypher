// MSSQL edges omit traversable to match MSSQLHound output.

CREATE (site:SCCM_Site:SCCM_Base:Base {
  siteCode: 'P01',
  displayName: 'Primary Site',
  objectid: 'P01',
  sourceForest: 'TEST.LOCAL'
});

CREATE (otherSite:SCCM_Site:SCCM_Base:Base {
  siteCode: 'X01',
  displayName: 'Other Forest Site',
  objectid: 'X01',
  sourceForest: 'OTHER.LOCAL'
});

CREATE (sccmServer:MSSQL_Server:MSSQL_Base:Base {
  name: 'sql01.test.local:1433',
  xpCmdShellEnabled: false,
  objectid: 'S-1-5-21-TEST-SQL01:1433'
});

CREATE (sccmDb:MSSQL_Database:MSSQL_Base:Base {
  name: 'CM_P01',
  SQLServer: 'sql01.test.local:1433'
});

CREATE (sysadmin:MSSQL_ServerRole:MSSQL_Base:Base {
  name: 'sysadmin',
  SQLServer: 'sql01.test.local:1433'
});

CREATE (dbOwner:MSSQL_DatabaseRole:MSSQL_Base:Base {
  name: 'db_owner@CM_P01',
  SQLServer: 'sql01.test.local:1433'
});

CREATE (fullRole:SCCM_SecurityRole:SCCM_Base:Base {
  name: 'Full Administrator'
});

CREATE (adminUser:SCCM_AdminUser:SCCM_Base:Base {
  name: 'TEST\\SCCM Admins',
  objectid: 'TEST\\SCCM Admins@P01',
  sourceSiteCode: 'P01',
  isGroup: true
});

CREATE (roleOnlyAdmin:SCCM_AdminUser:SCCM_Base:Base {
  name: 'TEST\\Role Admin',
  objectid: 'TEST\\Role Admin@P01',
  sourceSiteCode: 'P01'
});

CREATE (lowAdmin:SCCM_AdminUser:SCCM_Base:Base {
  name: 'TEST\\Low SCCM Group',
  objectid: 'TEST\\Low SCCM Group@P01',
  sourceSiteCode: 'P01',
  isGroup: true
});

CREATE (otherAdmin:SCCM_AdminUser:SCCM_Base:Base {
  name: 'OTHER\\SCCM Admins',
  objectid: 'OTHER\\SCCM Admins@X01',
  sourceSiteCode: 'X01'
});

CREATE (sccmGroup:Group:Base {
  name: 'SCCM ADMINS@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-SCCM-GROUP',
  domain: 'TEST.LOCAL'
});

CREATE (linkedSqlGroup:Group:Base {
  name: 'LINKED SQL USERS@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-LINKED-SQL-GROUP',
  domain: 'TEST.LOCAL'
});

CREATE (domainUsers:Group:Base {
  name: 'DOMAIN USERS@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-513',
  domain: 'TEST.LOCAL'
});

CREATE (lowGroup:Group:Base {
  name: 'LOW SCCM GROUP@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-LOW-GROUP',
  domain: 'TEST.LOCAL'
});

CREATE (otherGroup:Group:Base {
  name: 'OTHER SCCM GROUP@TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-OTHER-GROUP',
  domain: 'TEST.LOCAL'
});

CREATE (pureUser:User:Base {name: 'PURE@TEST.LOCAL', objectid: 'S-1-5-21-TEST-100', enabled: true, domain: 'TEST.LOCAL'});
CREATE (nestedUser:User:Base {name: 'NESTED@TEST.LOCAL', objectid: 'S-1-5-21-TEST-101', enabled: true, domain: 'TEST.LOCAL'});
CREATE (sqlUser:User:Base {name: 'SQLSYS@TEST.LOCAL', objectid: 'S-1-5-21-TEST-102', enabled: true, domain: 'TEST.LOCAL'});
CREATE (dbUserPrincipal:User:Base {name: 'SQLDB@TEST.LOCAL', objectid: 'S-1-5-21-TEST-103', enabled: true, domain: 'TEST.LOCAL'});
CREATE (linkedUser:User:Base {name: 'LINKED@TEST.LOCAL', objectid: 'S-1-5-21-TEST-104', enabled: true, domain: 'TEST.LOCAL'});
CREATE (alterUser:User:Base {name: 'ALTER@TEST.LOCAL', objectid: 'S-1-5-21-TEST-105', enabled: true, domain: 'TEST.LOCAL'});
CREATE (roleOnlyUser:User:Base {name: 'ROLEONLY@TEST.LOCAL', objectid: 'S-1-5-21-TEST-106', enabled: true, domain: 'TEST.LOCAL'});
CREATE (groupLinkedUser:User:Base {name: 'GROUPLINKED@TEST.LOCAL', objectid: 'S-1-5-21-TEST-107', enabled: true, domain: 'TEST.LOCAL'});
CREATE (broadLinkedUser:User:Base {name: 'BROADLINKED@TEST.LOCAL', objectid: 'S-1-5-21-TEST-108', enabled: true, domain: 'TEST.LOCAL'});
CREATE (execHostUser:User:Base {name: 'EXECCHAIN@TEST.LOCAL', objectid: 'S-1-5-21-TEST-109', enabled: true, domain: 'TEST.LOCAL'});
CREATE (sqlServiceAccount:User:Base:Tag_Tier_Zero {name: 'SQLSVC@TEST.LOCAL', objectid: 'S-1-5-21-TEST-SQLSVC', enabled: true, domain: 'TEST.LOCAL'});
CREATE (connectOnlyUser:User:Base {name: 'CONNECTONLY@TEST.LOCAL', objectid: 'S-1-5-21-TEST-200', enabled: true, domain: 'TEST.LOCAL'});
CREATE (lowSccmUser:User:Base {name: 'LOWSCCM@TEST.LOCAL', objectid: 'S-1-5-21-TEST-201', enabled: true, domain: 'TEST.LOCAL'});
CREATE (crossForestUser:User:Base {name: 'CROSSFOREST@TEST.LOCAL', objectid: 'S-1-5-21-TEST-202', enabled: true, domain: 'TEST.LOCAL'});
CREATE (disabledExecUser:User:Base {name: 'DISABLEDEXEC@TEST.LOCAL', objectid: 'S-1-5-21-TEST-203', enabled: true, domain: 'TEST.LOCAL'});
CREATE (noAdminLinkUser:User:Base {name: 'NOADMINLINK@TEST.LOCAL', objectid: 'S-1-5-21-TEST-204', enabled: true, domain: 'TEST.LOCAL'});

CREATE (n1:Group:Base {name: 'N1@TEST.LOCAL', objectid: 'S-1-5-21-TEST-N1', domain: 'TEST.LOCAL'});
CREATE (n2:Group:Base {name: 'N2@TEST.LOCAL', objectid: 'S-1-5-21-TEST-N2', domain: 'TEST.LOCAL'});
CREATE (n3:Group:Base {name: 'N3@TEST.LOCAL', objectid: 'S-1-5-21-TEST-N3', domain: 'TEST.LOCAL'});
CREATE (n4:Group:Base {name: 'N4@TEST.LOCAL', objectid: 'S-1-5-21-TEST-N4', domain: 'TEST.LOCAL'});
CREATE (n5:Group:Base {name: 'N5@TEST.LOCAL', objectid: 'S-1-5-21-TEST-N5', domain: 'TEST.LOCAL'});
CREATE (n6:Group:Base {name: 'N6@TEST.LOCAL', objectid: 'S-1-5-21-TEST-N6', domain: 'TEST.LOCAL'});

CREATE (sqlLogin:MSSQL_Login:MSSQL_Base:Base {name: 'TEST\\sqlsys', SQLServer: 'sql01.test.local:1433'});
CREATE (dbLogin:MSSQL_Login:MSSQL_Base:Base {name: 'TEST\\sqldb', SQLServer: 'sql01.test.local:1433'});
CREATE (dbMappedUser:MSSQL_DatabaseUser:MSSQL_Base:Base {name: 'sqldb@CM_P01', SQLServer: 'sql01.test.local:1433'});
CREATE (alterLogin:MSSQL_Login:MSSQL_Base:Base {name: 'TEST\\alter', SQLServer: 'sql01.test.local:1433'});
CREATE (connectLogin:MSSQL_Login:MSSQL_Base:Base {name: 'TEST\\connectonly', SQLServer: 'sql01.test.local:1433'});

CREATE (linkedSource:MSSQL_Server:MSSQL_Base:Base {
  name: 'lab-sql01.test.local:1433',
  sqlServerName: 'lab-sql01\\SQL01',
  objectid: 'S-1-5-21-TEST-LABSQL:1433'
});
CREATE (linkedTargetStub:MSSQL_Server:MSSQL_Base:Base {name: 'sql01.test.local'});
CREATE (linkedLogin:MSSQL_Login:MSSQL_Base:Base {name: 'TEST\\linked', SQLServer: 'lab-sql01.test.local:1433'});
CREATE (linkedGroupLogin:MSSQL_Login:MSSQL_Base:Base {name: 'TEST\\linked-group', SQLServer: 'lab-sql01.test.local:1433'});
CREATE (linkedBroadLogin:MSSQL_Login:MSSQL_Base:Base {name: 'TEST\\Domain Users', SQLServer: 'lab-sql01.test.local:1433'});
CREATE (execLogin:MSSQL_Login:MSSQL_Base:Base {name: 'TEST\\execchain', SQLServer: 'lab-sql01.test.local:1433'});
CREATE (execAssumedLogin:MSSQL_Login:MSSQL_Base:Base {name: 'ReportSvc', SQLServer: 'lab-sql01.test.local:1433'});

CREATE (sccmHost:Computer:Base {
  name: 'SCCMSQL.TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-SCCM-SQL',
  enabled: true,
  domain: 'TEST.LOCAL',
  SCCMSiteSystemRoles: ['SMS SQL Server@P01']
});

CREATE (disabledSource:MSSQL_Server:MSSQL_Base:Base {
  name: 'disabled-src.test.local:1433',
  sqlServerName: 'disabled-src\\SQL01',
  objectid: 'S-1-5-21-TEST-DISABLED-SRC:1433'
});
CREATE (disabledTargetStub:MSSQL_Server:MSSQL_Base:Base {name: 'disabled-sccm.test.local'});
CREATE (disabledTarget:MSSQL_Server:MSSQL_Base:Base {name: 'disabled-sccm.test.local:1433'});
CREATE (disabledLogin:MSSQL_Login:MSSQL_Base:Base {name: 'TEST\\disabledexec', SQLServer: 'disabled-src.test.local:1433'});
CREATE (disabledAssumedLogin:MSSQL_Login:MSSQL_Base:Base {name: 'DisabledExecSvc', SQLServer: 'disabled-src.test.local:1433'});
CREATE (disabledHost:Computer:Base {
  name: 'DISABLED-SCCM.TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-DISABLED-HOST',
  enabled: false,
  domain: 'TEST.LOCAL',
  SCCMSiteSystemRoles: ['SMS SQL Server@P01']
});

CREATE (noAdminSource:MSSQL_Server:MSSQL_Base:Base {
  name: 'noadmin-src.test.local:1433',
  sqlServerName: 'noadmin-src\\SQL01',
  objectid: 'S-1-5-21-TEST-NOADMIN-SRC:1433'
});
CREATE (noAdminTargetStub:MSSQL_Server:MSSQL_Base:Base {name: 'noadmin-sccm.test.local'});
CREATE (noAdminTarget:MSSQL_Server:MSSQL_Base:Base {name: 'noadmin-sccm.test.local:1433'});
CREATE (noAdminLogin:MSSQL_Login:MSSQL_Base:Base {name: 'TEST\\noadminlink', SQLServer: 'noadmin-src.test.local:1433'});
CREATE (noAdminAssumedLogin:MSSQL_Login:MSSQL_Base:Base {name: 'NoAdminExecSvc', SQLServer: 'noadmin-src.test.local:1433'});
CREATE (noAdminHost:Computer:Base {
  name: 'NOADMIN-SCCM.TEST.LOCAL',
  objectid: 'S-1-5-21-TEST-NOADMIN-HOST',
  enabled: true,
  domain: 'TEST.LOCAL',
  SCCMSiteSystemRoles: ['SMS SQL Server@P01']
});

MATCH (sccmServer:MSSQL_Server {name: 'sql01.test.local:1433'}),
      (sccmDb:MSSQL_Database {name: 'CM_P01'}),
      (site:SCCM_Site {siteCode: 'P01'}),
      (sysadmin:MSSQL_ServerRole {name: 'sysadmin'}),
      (dbOwner:MSSQL_DatabaseRole {name: 'db_owner@CM_P01'}),
      (adminUser:SCCM_AdminUser {objectid: 'TEST\\SCCM Admins@P01'}),
      (roleOnlyAdmin:SCCM_AdminUser {objectid: 'TEST\\Role Admin@P01'}),
      (fullRole:SCCM_SecurityRole {name: 'Full Administrator'})
CREATE (sccmServer)-[:MSSQL_Contains]->(sccmDb)
CREATE (sccmServer)-[:MSSQL_Contains]->(sysadmin)
CREATE (sysadmin)-[:MSSQL_ControlServer]->(sccmServer)
CREATE (sccmDb)-[:MSSQL_Contains]->(dbOwner)
CREATE (sccmDb)-[:SCCM_AssignAllPermissions]->(site)
CREATE (adminUser)-[:SCCM_AllPermissions]->(site)
CREATE (adminUser)-[:SCCM_IsAssigned]->(fullRole)
CREATE (roleOnlyAdmin)-[:SCCM_IsAssigned]->(fullRole);

MATCH (pureUser:User {objectid: 'S-1-5-21-TEST-100'}),
      (nestedUser:User {objectid: 'S-1-5-21-TEST-101'}),
      (sccmGroup:Group {objectid: 'S-1-5-21-TEST-SCCM-GROUP'}),
      (adminUser:SCCM_AdminUser {objectid: 'TEST\\SCCM Admins@P01'}),
      (n1:Group {objectid: 'S-1-5-21-TEST-N1'}),
      (n2:Group {objectid: 'S-1-5-21-TEST-N2'}),
      (n3:Group {objectid: 'S-1-5-21-TEST-N3'}),
      (n4:Group {objectid: 'S-1-5-21-TEST-N4'}),
      (n5:Group {objectid: 'S-1-5-21-TEST-N5'}),
      (n6:Group {objectid: 'S-1-5-21-TEST-N6'})
CREATE (pureUser)-[:MemberOf]->(sccmGroup)
CREATE (sccmGroup)-[:SCCM_IsMappedTo]->(adminUser)
CREATE (nestedUser)-[:MemberOf]->(n1)
CREATE (n1)-[:MemberOf]->(n2)
CREATE (n2)-[:MemberOf]->(n3)
CREATE (n3)-[:MemberOf]->(n4)
CREATE (n4)-[:MemberOf]->(n5)
CREATE (n5)-[:MemberOf]->(n6)
CREATE (n6)-[:SCCM_IsMappedTo]->(adminUser);

MATCH (sqlUser:User {objectid: 'S-1-5-21-TEST-102'}),
      (sqlLogin:MSSQL_Login {name: 'TEST\\sqlsys'}),
      (sysadmin:MSSQL_ServerRole {name: 'sysadmin'}),
      (dbUserPrincipal:User {objectid: 'S-1-5-21-TEST-103'}),
      (dbLogin:MSSQL_Login {name: 'TEST\\sqldb'}),
      (dbMappedUser:MSSQL_DatabaseUser {name: 'sqldb@CM_P01'}),
      (dbOwner:MSSQL_DatabaseRole {name: 'db_owner@CM_P01'}),
      (alterUser:User {objectid: 'S-1-5-21-TEST-105'}),
      (alterLogin:MSSQL_Login {name: 'TEST\\alter'}),
      (connectOnlyUser:User {objectid: 'S-1-5-21-TEST-200'}),
      (connectLogin:MSSQL_Login {name: 'TEST\\connectonly'}),
      (sccmServer:MSSQL_Server {name: 'sql01.test.local:1433'})
CREATE (sqlUser)-[:MSSQL_HasLogin]->(sqlLogin)
CREATE (sqlLogin)-[:MSSQL_MemberOf]->(sysadmin)
CREATE (dbUserPrincipal)-[:MSSQL_HasLogin]->(dbLogin)
CREATE (dbLogin)-[:MSSQL_IsMappedTo]->(dbMappedUser)
CREATE (dbMappedUser)-[:MSSQL_MemberOf]->(dbOwner)
CREATE (alterUser)-[:MSSQL_HasLogin]->(alterLogin)
CREATE (alterLogin)-[:MSSQL_Connect]->(sccmServer)
CREATE (alterLogin)-[:MSSQL_AlterAnyLogin]->(sccmServer)
CREATE (connectOnlyUser)-[:MSSQL_HasLogin]->(connectLogin)
CREATE (connectLogin)-[:MSSQL_Connect]->(sccmServer);

MATCH (linkedUser:User {objectid: 'S-1-5-21-TEST-104'}),
      (groupLinkedUser:User {objectid: 'S-1-5-21-TEST-107'}),
      (broadLinkedUser:User {objectid: 'S-1-5-21-TEST-108'}),
      (linkedSqlGroup:Group {objectid: 'S-1-5-21-TEST-LINKED-SQL-GROUP'}),
      (domainUsers:Group {objectid: 'S-1-5-21-TEST-513'}),
      (linkedLogin:MSSQL_Login {name: 'TEST\\linked'}),
      (linkedGroupLogin:MSSQL_Login {name: 'TEST\\linked-group'}),
      (linkedBroadLogin:MSSQL_Login {name: 'TEST\\Domain Users'}),
      (linkedSource:MSSQL_Server {name: 'lab-sql01.test.local:1433'}),
      (linkedTargetStub:MSSQL_Server {name: 'sql01.test.local'})
CREATE (linkedUser)-[:MSSQL_HasLogin]->(linkedLogin)
CREATE (linkedLogin)-[:MSSQL_Connect]->(linkedSource)
CREATE (groupLinkedUser)-[:MemberOf]->(linkedSqlGroup)
CREATE (linkedSqlGroup)-[:MSSQL_HasLogin]->(linkedGroupLogin)
CREATE (linkedGroupLogin)-[:MSSQL_Connect]->(linkedSource)
CREATE (broadLinkedUser)-[:MemberOf]->(domainUsers)
CREATE (domainUsers)-[:MSSQL_HasLogin]->(linkedBroadLogin)
CREATE (linkedBroadLogin)-[:MSSQL_Connect]->(linkedSource)
CREATE (linkedSource)-[:MSSQL_LinkedAsAdmin]->(linkedTargetStub);

MATCH (execHostUser:User {objectid: 'S-1-5-21-TEST-109'}),
      (execLogin:MSSQL_Login {name: 'TEST\\execchain'}),
      (execAssumedLogin:MSSQL_Login {name: 'ReportSvc'}),
      (linkedSource:MSSQL_Server {name: 'lab-sql01.test.local:1433'}),
      (sccmServer:MSSQL_Server {name: 'sql01.test.local:1433'}),
      (sqlServiceAccount:User {objectid: 'S-1-5-21-TEST-SQLSVC'}),
      (sccmHost:Computer {objectid: 'S-1-5-21-TEST-SCCM-SQL'}),
      (site:SCCM_Site {siteCode: 'P01'})
CREATE (execHostUser)-[:MSSQL_HasLogin]->(execLogin)
CREATE (execLogin)-[:MSSQL_Connect]->(linkedSource)
CREATE (execLogin)-[:MSSQL_ExecuteAs]->(execAssumedLogin)
CREATE (execAssumedLogin)-[:MSSQL_Connect]->(linkedSource)
CREATE (sqlServiceAccount)-[:MSSQL_ServiceAccountFor]->(sccmServer)
CREATE (sccmServer)-[:MSSQL_ExecuteOnHost]->(sccmHost)
CREATE (sccmHost)-[:SCCM_AssignAllPermissions]->(site);

MATCH (disabledExecUser:User {objectid: 'S-1-5-21-TEST-203'}),
      (disabledLogin:MSSQL_Login {name: 'TEST\\disabledexec'}),
      (disabledAssumedLogin:MSSQL_Login {name: 'DisabledExecSvc'}),
      (disabledSource:MSSQL_Server {name: 'disabled-src.test.local:1433'}),
      (disabledTargetStub:MSSQL_Server {name: 'disabled-sccm.test.local'}),
      (disabledTarget:MSSQL_Server {name: 'disabled-sccm.test.local:1433'}),
      (disabledHost:Computer {objectid: 'S-1-5-21-TEST-DISABLED-HOST'}),
      (site:SCCM_Site {siteCode: 'P01'})
CREATE (disabledExecUser)-[:MSSQL_HasLogin]->(disabledLogin)
CREATE (disabledLogin)-[:MSSQL_ExecuteAs]->(disabledAssumedLogin)
CREATE (disabledAssumedLogin)-[:MSSQL_Connect]->(disabledSource)
CREATE (disabledSource)-[:MSSQL_LinkedAsAdmin {rpcOut: true}]->(disabledTargetStub)
CREATE (disabledTarget)-[:MSSQL_ExecuteOnHost]->(disabledHost)
CREATE (disabledHost)-[:SCCM_AssignAllPermissions]->(site);

MATCH (noAdminLinkUser:User {objectid: 'S-1-5-21-TEST-204'}),
      (noAdminLogin:MSSQL_Login {name: 'TEST\\noadminlink'}),
      (noAdminAssumedLogin:MSSQL_Login {name: 'NoAdminExecSvc'}),
      (noAdminSource:MSSQL_Server {name: 'noadmin-src.test.local:1433'}),
      (noAdminTargetStub:MSSQL_Server {name: 'noadmin-sccm.test.local'}),
      (noAdminTarget:MSSQL_Server {name: 'noadmin-sccm.test.local:1433'}),
      (noAdminHost:Computer {objectid: 'S-1-5-21-TEST-NOADMIN-HOST'}),
      (site:SCCM_Site {siteCode: 'P01'})
CREATE (noAdminLinkUser)-[:MSSQL_HasLogin]->(noAdminLogin)
CREATE (noAdminLogin)-[:MSSQL_ExecuteAs]->(noAdminAssumedLogin)
CREATE (noAdminAssumedLogin)-[:MSSQL_Connect]->(noAdminSource)
CREATE (noAdminSource)-[:MSSQL_LinkedTo {
  rpcOut: true,
  remoteIsSysadmin: false,
  remoteIsSecurityAdmin: false,
  remoteHasControlServer: false,
  remoteHasImpersonateAnyLogin: false
}]->(noAdminTargetStub)
CREATE (noAdminTarget)-[:MSSQL_ExecuteOnHost]->(noAdminHost)
CREATE (noAdminHost)-[:SCCM_AssignAllPermissions]->(site);

MATCH (roleOnlyUser:User {objectid: 'S-1-5-21-TEST-106'}),
      (roleOnlyAdmin:SCCM_AdminUser {objectid: 'TEST\\Role Admin@P01'})
CREATE (roleOnlyUser)-[:SCCM_IsMappedTo]->(roleOnlyAdmin);

MATCH (lowSccmUser:User {objectid: 'S-1-5-21-TEST-201'}),
      (lowGroup:Group {objectid: 'S-1-5-21-TEST-LOW-GROUP'}),
      (lowAdmin:SCCM_AdminUser {objectid: 'TEST\\Low SCCM Group@P01'})
CREATE (lowSccmUser)-[:MemberOf]->(lowGroup)
CREATE (lowGroup)-[:SCCM_IsMappedTo]->(lowAdmin);

MATCH (crossForestUser:User {objectid: 'S-1-5-21-TEST-202'}),
      (otherGroup:Group {objectid: 'S-1-5-21-TEST-OTHER-GROUP'}),
      (otherAdmin:SCCM_AdminUser {objectid: 'OTHER\\SCCM Admins@X01'}),
      (otherSite:SCCM_Site {siteCode: 'X01'})
CREATE (crossForestUser)-[:MemberOf]->(otherGroup)
CREATE (otherGroup)-[:SCCM_IsMappedTo]->(otherAdmin)
CREATE (otherAdmin)-[:SCCM_AllPermissions]->(otherSite);
