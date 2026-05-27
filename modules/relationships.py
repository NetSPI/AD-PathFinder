ABUSE_RELS = [
    'Owns', 'GenericAll', 'GenericWrite', 'WriteOwner', 'WriteDacl',
    'AdminTo', 'CanPSRemote', 'CanRDP', 'ForceChangePassword',
    'AllExtendedRights', 'AddMember', 'AddSelf', 'AllowedToDelegate', 'AllowedToAct',
    'AddAllowedToAct',
    'DCSync', 'ReadLAPSPassword', 'ReadGMSAPassword', 'SyncLAPSPassword',
    'DumpSMSAPassword', 'SQLAdmin',
    'WriteSPN', 'AddKeyCredentialLink', 'WriteAccountRestrictions',
    'GPLink', 'WriteGPLink', 'GoldenCert', 'ManageCA', 'ManageCertificates',
    'CoerceToTGT', 'CoerceAndRelayNTLMToADCS',
    'CoerceAndRelayNTLMToSMB', 'CoerceAndRelayNTLMToLDAP', 'CoerceAndRelayNTLMToLDAPS',
    'CoerceAndRelayToADCS', 'CoerceAndRelayToSMB', 'CoerceAndRelayToAdminService',
    'AbuseTGTDelegation', 'CrossForestTrust',
]

ESCALATION_RELS = ['MemberOf'] + ABUSE_RELS
