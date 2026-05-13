import re
import warnings


class Config:

    RELATIONSHIP_EXPLANATIONS = {
        "MemberOf": "is a member of the group",
        "AddMember": "can add members to the group",
        "AddSelf": "can add themselves to the group",
        "GenericAll": "has full control over",
        "WriteDacl": "can modify the security permissions of",
        "WriteOwner": "can change the owner of",
        "GenericWrite": "can modify attributes of",
        "AllExtendedRights": "has extended rights on",
        "Contains": "is a container that includes",
        "DCSync": "can perform DCSync operations against",
        "DumpSMSAPassword": "can retrieve the password of the managed service account",
        "GPLink": "is linked via Group Policy to",
        "Owns": "is the owner of",
        "ReadGMSAPassword": "can read the password of the managed service account",
        "ReadLAPSPassword": "can read the LAPS password of",
        "SQLAdmin": "has SQL admin rights on",
        "SyncLAPSPassword": "can synchronize the LAPS password of",
        "WriteGPLink": "can modify Group Policy links on",
        "WriteSPN": "can write Service Principal Names on",
        "HasSession": "has an active session on",
        "CanRDP": "can establish RDP connections to",
        "CanPSRemote": "can establish PowerShell Remoting connections to",
        "ExecuteDCOM": "can execute DCOM objects on",
        "AdminTo": "has administrative privileges on",
        "AddKeyCredential": "can add alternative credentials to",
        "AddKeyCredentialLink": "can add alternative credentials to",
        "CoerceToTGT": "can coerce to obtain a TGT for",
        "ForceChangePassword": "can force a password change for",
        "ChangePassword": "can change the password of",
        "AllowedToAct": "is allowed to act on behalf of",
        "AllowedToDelegate": "is allowed to delegate authentication to",
        "ADCSESC1": "can exploit ESC1 vulnerability (vulnerable certificate templates with Client Authentication EKU) against",
        "ADCSESC2": "can exploit ESC2 vulnerability (vulnerable certificate templates with Any Purpose EKU) against",
        "ADCSESC3": "has enrollment rights on vulnerable certificate templates for",
        "ADCSESC4": "can exploit ESC4 vulnerability (vulnerable misconfigured certificate templates ACL) on",
        "ADCSESC5": "can exploit ESC5 vulnerability (certificate template with lower requirements) on",
        "ADCSESC6a": "can exploit ESC6 vulnerability (EDITF_ATTRIBUTESUBJECTALTNAME2 Enabled) on",
        "ADCSESC6b": "can exploit ESC6 vulnerability (EDITF_ATTRIBUTESUBJECTALTNAME2 Enabled) on",
        "ADCSESC7": "can exploit ESC7 vulnerability (vulnerable certificate authority access control) on",
        "ADCSESC8": "can perform NTLM relay to AD CS HTTP endpoints on",
        "ADCSESC9a": "can exploit ESC9 vulnerability (no security extensions) on",
        "ADCSESC9b": "can exploit ESC9 vulnerability (no security extensions) on",
        "ADCSESC10a": "can exploit ESC10 vulnerability (weak certificate mappings) on",
        "ADCSESC10b": "can exploit ESC10 vulnerability (weak certificate mappings) on",
        "ADCSESC11": "can exploit ESC11 vulnerability (relaying to ICPR) on",
        "ADCSESC12": "can exploit ESC12 vulnerability (vulnerable PKI object ACL) on",
        "ADCSESC13": "can exploit ESC13 vulnerability (vulnerable certificate issuance approval) on",
        "GoldenCert": "can use Golden Certificate attack against",
        "ManageCA": "has CA Manager rights on",
        "ManageCertificates": "has rights to manage certificates on",
        "WriteAccountRestrictions": "can modify account restrictions of",
        "CoerceAndRelayNTLMToADCS": "can coerce authentication and relay NTLM to AD CS on",
    }

    RELATIONSHIP_IMPACTS = {
        "MemberOf": ["inheritance of all permissions and privileges of the group, effectively gaining its complete access rights and capabilities even if the group possesses privileged access, allowing an attacker to gain elevated permissions without requiring additional exploitation steps."],
        "AddMember": ["strategic placement of compromised accounts into privileged groups, creating direct paths to sensitive resources and facilitating persistent backdoor access through rogue accounts."],
        "AddSelf": ["autonomous addition to the target group without administrative approval, immediately inheriting all privileges, permissions and access rights of the target group."],
        "GenericAll": ["unrestricted control over the target object, including the ability to reset passwords, modify security attributes, and enable attack techniques such as Resource-Based Constrained Delegation or Kerberoasting."],
        "WriteDacl": ["modification of the security descriptor access control list, effectively allowing an attacker to grant themselves additional permissions including GenericAll or other elevated access rights."],
        "WriteOwner": ["changing of the object's ownership to an attacker's account, granting implicit rights to modify all security settings, permissions, attributes and configurations of the target."],
        "GenericWrite": ["modification of critical object attributes including the servicePrincipalName property which can be exploited for Kerberoasting attacks and enables configuration of Resource-Based Constrained Delegation for credential theft."],
        "AllExtendedRights": ["access to special privileged operations including password resets and forced password changes without knowing the current password whilst providing the ability to read sensitive security attributes."],
        "Contains": ["control over a container object whereby permissions affect all nested objects through inheritance mechanisms and allows deployment of malicious Group Policy Objects that can compromise all child objects within its scope."],
        "DCSync": ["simulation of a domain controller to extract password hashes for all domain accounts including administrators and service accounts, enabling complete domain compromise."],
        "DumpSMSAPassword": ["direct retrieval of standalone managed service account passwords, providing credentials for privileged service accounts that can be leveraged for lateral movement and privilege escalation."],
        "GPLink": ["exploitation of existing Group Policy Object links to deploy malicious scripts, scheduled tasks, and security settings to the target whilst providing control over critical security configurations affecting all linked systems."],
        "Owns": ["ownership rights that grant implicit privileges to modify permissions and attributes of the owned object, enabling password resets and privilege delegation for further network compromise."],
        "ReadGMSAPassword": ["extraction of group managed service account passwords, providing privileged credentials that can be leveraged for lateral movement and impersonation across the domain."],
        "ReadLAPSPassword": ["access to local administrator passwords managed by the Local Administrator Password Solution for target computers, enabling direct administrative access for remote command execution and system compromise."],
        "SQLAdmin": ["administrative privileges for executing arbitrary SQL commands, accessing sensitive data, and potentially executing operating system commands through SQL Server extended functionality."],
        "SyncLAPSPassword": ["modification of LAPS managed local administrator passwords, enabling creation of backdoor access to systems by setting known passwords for future exploitation."],
        "WriteGPLink": ["control over which Group Policy Objects are applied to the target, enabling deployment of malicious settings through newly linked policies that can execute attacker controlled code."],
        "WriteSPN": ["creation of Service Principal Names on the target account, making it vulnerable to Kerberoasting attacks where service account passwords can be cracked offline."],
        "HasSession": ["targeting of active user sessions for credential dumping attacks where memory resident credentials may be extracted from LSASS or through token impersonation techniques."],
        "CanRDP": ["Remote Desktop Protocol access for interactive login sessions to the target system, allowing command execution with the security context and privileges of the authenticated user."],
        "CanPSRemote": ["remote PowerShell command execution capabilities on the target system, allowing script execution and command invocation with the privileges of the connecting account."],
        "ExecuteDCOM": ["execution of Distributed COM objects for remote command execution, potentially with elevated privileges depending on the configuration of the DCOM application."],
        "AdminTo": ["full administrative control over the target system, enabling execution of arbitrary commands, credential theft from memory, persistence mechanism establishment, and complete system compromise."],
        "AddKeyCredential": ["addition of Shadow Credentials to the target account, enabling authentication as the target without knowing or changing the original password through certificate-based authentication."],
        "AddKeyCredentialLink": ["addition of Shadow Credentials to the target account, enabling authentication as the target without knowing or changing the original password through certificate-based authentication."],
        "CoerceToTGT": ["forcing the target to authenticate to an attacker-controlled system where authentication material can be captured for relay attacks or offline password cracking."],
        "ForceChangePassword": ["resetting of the target account's password without knowing the current password, enabling complete account takeover for accessing resources or further privilege escalation."],
        "ChangePassword": ["changing of the target account's password with knowledge of the current password, enabling account takeover for accessing privileged resources and services."],
        "AllowedToAct": ["abuse of Resource-Based Constrained Delegation to impersonate users to specific services, allowing authentication as the target account when accessing the compromised system."],
        "AllowedToDelegate": ["impersonation of other users in specific contexts through delegation, enabling authentication as the target user to designated services for lateral movement."],
        "ADCSESC1": ["exploitation of vulnerable certificate templates with overly permissive enrollment rights to request certificates for any identity, including domain administrators for privilege escalation."],
        "ADCSESC2": ["targeting of certificate templates configured with the Any Purpose EKU, allowing creation of certificates that can be abused for various authentication scenarios and credential theft."],
        "ADCSESC3": ["abuse of Certificate Request Agent EKU to request certificates on behalf of other users, enabling impersonation of privileged accounts through fraudulent certificate requests."],
        "ADCSESC4": ["modification of certificate template configurations to introduce security vulnerabilities, enabling reconfiguration of templates for subsequent exploitation through other ESC vulnerabilities."],
        "ADCSESC5": ["requesting of certificates with less stringent requirements than intended through name constraints bypasses, circumventing security controls for unauthorized certificate acquisition."],
        "ADCSESC6a": ["exploitation of the EDITF_ATTRIBUTESUBJECTALTNAME2 flag on Certificate Authorities to specify arbitrary Subject Alternative Names, allowing certificate requests for any identity regardless of template restrictions."],
        "ADCSESC6b": ["combination of EDITF_ATTRIBUTESUBJECTALTNAME2 flag with ESC10 to bypass the May 2022 security patches, enabling continued certificate requests for unauthorized identities."],
        "ADCSESC7": ["leveraging of Manage CA or Manage Certificates rights to approve previously denied certificate requests, enabling issuance of certificates with elevated privileges despite security controls."],
        "ADCSESC8": ["performing of NTLM relay attacks against Active Directory Certificate Services Web Enrollment over HTTP, capturing authentication and relaying it to obtain fraudulent certificates for privileged accounts."],
        "ADCSESC9a": ["exploitation of certificate templates lacking proper security extensions, allowing certificate misuse in specific scenarios due to missing or inadequate security controls."],
        "ADCSESC9b": ["abuse of certificate templates without proper security extension validation, enabling certificate-based attacks due to improper validation of critical security attributes during issuance."],
        "ADCSESC10a": ["targeting of weak certificate mapping configurations where Subject Alternative Name is preferred over UPN, facilitating authentication certificate mapping vulnerabilities for privilege escalation."],
        "ADCSESC10b": ["combination with ESC6 to exploit weak certificate mapping mechanisms, bypassing multiple layers of security controls through vulnerability chaining for maximum impact."],
        "ADCSESC11": ["attacks on Certificate Authorities not configured with the IF_ENFORCEENCRYPTICERTREQUEST flag, enabling NTLM relay attacks against vulnerable RPC interfaces without required signing."],
        "ADCSESC12": ["exploitation of vulnerable access control lists on PKI objects to compromise the certificate infrastructure, allowing manipulation of PKI objects to gain unauthorized certificate issuance capabilities."],
        "ADCSESC13": ["targeting of vulnerable certificate issuance approval processes, bypassing approval requirements to obtain unauthorized certificates for privileged identities."],
        "GoldenCert": ["creation of a certificate usable for persistent domain authentication, providing long-term privileged access similar to Golden Ticket attacks but with greater persistence."],
        "ManageCA": ["administrative control over the Certificate Authority, enabling issuance of arbitrary certificates and complete subversion of the PKI infrastructure."],
        "ManageCertificates": ["manipulation of certificate requests and issuance processes, allowing approval, denial, or modification of certificate requests to serve the attacker's objectives."],
        "WriteAccountRestrictions": ["modification of sensitive account security settings, allowing changes to User Account Control flags, account restrictions, and security-related attributes that can be leveraged for privilege escalation."],
        "CoerceAndRelayNTLMToADCS": ["coercion of machine account authentication and relay to AD CS web enrollment endpoints, enabling an attacker to obtain a certificate for the machine account which can be used for authentication and privilege escalation."],
    }

    DEFAULT_IMPACTS = [
        "Provides a potential attack vector in the escalation chain",
        "Could be leveraged for lateral movement or privilege escalation"
    ]

    GPO_IMPACTS = [
        "modification of Group Policy Object settings to deploy malicious configurations across the domain. This allows an attacker to execute arbitrary code via startup/logon scripts, alter critical security settings like administrative group memberships, deploy malicious software, and modify system configurations for persistence. These changes affect all computers and users within linked OUs, enabling widespread compromise and lateral movement throughout the domain."
    ]

    OU_IMPACTS = [
        "comprehensive control over the Organizational Unit, including management of all contained objects, linking of malicious GPOs, creation and modification of user and computer accounts, and alteration of security settings affecting all child objects. This level of access allows an attacker to compromise accounts, deploy malicious configurations, and potentially gain administrative control over all systems within the OU structure."
    ]

    # Well-known AD schema/extended-rights GUIDs used in PowerShell ACL checks
    GUID_DS_REPL_GET_CHANGES      = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
    GUID_DS_REPL_GET_CHANGES_ALL  = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    GUID_MEMBER_ATTR              = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
    GUID_GPLINK_ATTR              = 'f30e3bbe-9ff0-11d1-b603-0000f80367c1'
    GUID_SPN_ATTR                 = 'f3a64788-5306-11d1-a9c5-0000f80367c1'
    GUID_KEY_CREDENTIAL_LINK      = '5b47d60f-6090-40b2-9f37-2a4de88f3063'
    GUID_LAPS_PASSWORD            = 'eefff90f-a3d8-4529-a37c-1bb359dac3a3'
    GUID_LAPS_EXPIRATION          = '28630ebf-41d5-11d1-a9c1-0000f80367c1'
    GUID_FORCE_CHANGE_PASSWORD    = '00299570-246d-11d0-a768-00aa006e0529'
    GUID_USER_CHANGE_PASSWORD     = 'ab721a53-1e2f-11d0-9819-00aa0040529b'
    GUID_ACCOUNT_RESTRICTIONS     = '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'

    ACL_RELATIONSHIPS = [
        "MemberOf", "GenericAll", "WriteDacl", "WriteOwner", "GenericWrite",
        "AllExtendedRights", "Contains", "DCSync", "DumpSMSAPassword", "GPLink",
        "Owns", "ReadGMSAPassword", "ReadLAPSPassword", "SQLAdmin", "SyncLAPSPassword",
        "WriteGPLink", "WriteSPN", "HasSession", "CanRDP", "CanPSRemote",
        "ExecuteDCOM", "AdminTo", "AddKeyCredential", "AddKeyCredentialLink", "CoerceToTGT",
        "ForceChangePassword", "ChangePassword", "AllowedToAct", "AllowedToDelegate",
        "AddMember", "AddSelf"
    ]

    ADCS_RELATIONSHIPS = [
        'ADCSESC1', 'ADCSESC2', 'ADCSESC3', 'ADCSESC4', 'ADCSESC5',
        'ADCSESC6a', 'ADCSESC6b', 'ADCSESC7', 'ADCSESC8',
        'ADCSESC9a', 'ADCSESC9b', 'ADCSESC10a', 'ADCSESC10b',
        'ADCSESC11', 'ADCSESC12', 'ADCSESC13',
        'GoldenCert',
        'ManageCA', 'ManageCertificates'
    ]


class Utils:

    @staticmethod
    def get_formatted_object_type(object_detail):
        if not object_detail or not isinstance(object_detail, dict):
            return ""

        object_type = object_detail.get('type', '')

        if not object_type and 'labels' in object_detail:
            labels = object_detail['labels']
            if isinstance(labels, list) and len(labels) > 0:
                priority_types = [
                    'User', 'Computer', 'Group', 'GPO', 'OU', 'Domain',
                    'Container', 'CertTemplate', 'CertificateTemplate',
                    'EnterpriseCA', 'RootCA', 'AIACA', 'NTAuthStore',
                    'IssuancePolicy', 'MSSQL_Server', 'MSSQL_Database',
                    'MSSQL_Login', 'MSSQL_ServerRole', 'MSSQL_DatabaseRole'
                ]

                for ptype in priority_types:
                    if ptype in labels:
                        object_type = ptype
                        break

                if not object_type:
                    for label in labels:
                        if label not in ['Base', 'ADLocalGroup', 'LocalGroup']:
                            object_type = label
                            break

                    if not object_type:
                        object_type = labels[0]

        if not object_type and 'dn' in object_detail:
            dn = object_detail['dn']
            if isinstance(dn, str):
                if 'CN=COMPUTERS' in dn.upper():
                    object_type = 'Computer'
                elif 'CN=USERS' in dn.upper():
                    object_type = 'User'
                elif 'CN=CERTIFICATE TEMPLATES' in dn.upper():
                    object_type = 'CertificateTemplate'
                elif 'CN=GROUP POLICY' in dn.upper():
                    object_type = 'GPO'
                elif 'OU=' in dn.upper():
                    object_type = 'OU'
                elif 'CN=BUILTIN' in dn.upper():
                    object_type = 'Group'

        if not object_type and 'objectClass' in object_detail:
            object_classes = object_detail['objectClass']
            if isinstance(object_classes, list):
                for cls in object_classes:
                    if cls.lower() == 'user':
                        object_type = 'User'
                    elif cls.lower() == 'computer':
                        object_type = 'Computer'
                    elif cls.lower() == 'group':
                        object_type = 'Group'
                    elif cls.lower() == 'grouppolicycontainer':
                        object_type = 'GPO'

        if object_type:
            if object_type.upper() == 'GPO':
                return 'GPO'
            elif object_type.upper() == 'OU':
                return 'OU'
            elif object_type.lower() == 'certificatetemplate':
                return 'Certificate Template'
            else:
                return object_type[0].upper() + object_type[1:].lower()

        return ""

    @staticmethod
    def get_well_known_sid(source_name_lower, domain_sid):
        if not domain_sid:
            domain_sid = "S-1-5-21-domain"

        if source_name_lower == "domain users":
            return f"{domain_sid}-513"
        elif source_name_lower == "authenticated users":
            return "S-1-5-11"
        elif source_name_lower == "domain computers":
            return f"{domain_sid}-515"
        elif source_name_lower == "everyone":
            return "S-1-1-0"
        elif source_name_lower == "domain admins":
            return f"{domain_sid}-512"
        return None

    @staticmethod
    def get_server_parameter_string(domain_controller):
        if domain_controller and isinstance(domain_controller, str) and domain_controller.strip():
            dc_lowercase = domain_controller.strip().lower()
            return f' -server "{dc_lowercase}"'
        else:
            return ""

    @staticmethod
    def get_element_string(element):
        if element is None:
            return None
        elif isinstance(element, dict):
            return element.get('name', str(element))
        else:
            return str(element)

    @staticmethod
    def extract_domain_metadata(json_data):
        metadata = json_data.get('metadata', {})
        domain_name = metadata.get('domain')
        domain_controller = metadata.get('enabled_dc_fqdn')
        domain_sid = metadata.get('domain_sid')

        if not domain_name or not isinstance(domain_name, str) or not domain_name.strip():
            warnings.warn("Domain name not found in input JSON metadata. Asset domain information will be missing.")
            domain_name = "UNKNOWN_DOMAIN"
        else:
            print(f"Processing domain: {domain_name}")

        if not domain_controller or not isinstance(domain_controller, str) or not domain_controller.strip():
            warnings.warn("Domain controller FQDN not found in JSON metadata. Using default DC discovery.")
            domain_controller = None
        else:
            print(f"Using domain controller: {domain_controller}")

        if not domain_sid:
            warnings.warn("Domain SID not found in JSON metadata. Using placeholder for well-known group SIDs.")
        else:
            print(f"Using domain SID: {domain_sid}")

        domain_distinguished_name = Utils.get_domain_dn(domain_name)

        return domain_name, domain_controller, domain_sid, domain_distinguished_name

    @staticmethod
    def get_domain_dn(domain_name):
        if not domain_name or domain_name == "UNKNOWN_DOMAIN":
            return "DC=UNKNOWN_DOMAIN"

        domain_parts = domain_name.split('.')
        return ','.join([f"DC={part}" for part in domain_parts])


class PowerShellCommandGenerator:

    def __init__(self, domain_controller, domain_name, domain_sid):
        self.domain_controller = domain_controller
        self.domain_name = domain_name
        self.domain_sid = domain_sid
        self.server_flag = Utils.get_server_parameter_string(domain_name)
        self.domain_dn = f"DC={domain_name.replace('.', ',DC=')}" if domain_name != "UNKNOWN_DOMAIN" else "DC=UNKNOWN_DOMAIN"

    def generate_relationship_command(self, relationship, source_name, target_name, source_detail, target_detail, asset_identity_ad_object_sid):

        source_user = source_name.split('@')[0] if '@' in source_name else source_name
        target_user = target_name.split('@')[0] if '@' in target_name else target_name

        actual_source_sid = asset_identity_ad_object_sid
        if source_detail and isinstance(source_detail, dict) and 'sid' in source_detail:
            actual_source_sid = source_detail['sid']

        well_known_sid = Utils.get_well_known_sid(source_name.lower(), self.domain_sid)
        if well_known_sid and (not actual_source_sid or "domain" in actual_source_sid):
            actual_source_sid = well_known_sid

        target_sid = None
        if target_detail and isinstance(target_detail, dict):
            raw_sid = target_detail.get('sid') or target_detail.get('objectid')
            if raw_sid:
                if '-S-1-' in raw_sid and not raw_sid.startswith('S-1-'):
                    idx = raw_sid.rfind('-S-1-')
                    if idx > 0:
                        target_sid = 'S-1' + raw_sid[idx + 4:]
                else:
                    target_sid = raw_sid

        target_type = Utils.get_formatted_object_type(target_detail).upper() if target_detail else ''
        target_dn = target_detail.get('dn') if target_detail and isinstance(target_detail, dict) else None

        return self._get_command_for_relationship(
            relationship, source_user, target_user, actual_source_sid, target_sid,
            target_type, target_dn, source_detail, target_detail
        )

    def _get_command_for_relationship(self, relationship, source_user, target_user, source_sid, target_sid, target_type, target_dn, source_detail, target_detail):
        if relationship == "DCSync":
            return self._generate_dcsync_command(source_sid)
        elif relationship == "MemberOf":
            return self._generate_memberof_command(source_sid, target_user, target_sid)
        elif relationship == "GoldenCert":
            return f"The object {source_user} has access to a certificate private key that can be abused to sign \"golden\" certificates for authentication of any enabled principal in the AD forest of domain {self.domain_name}. This private key allows an attacker to sign certificates for authentication as any enabled principal in the AD forest of domain {self.domain_name}, as the enterprise CA is trusted for NT authentication and chains up to a root CA."
        elif relationship == "CoerceToTGT":
            return self._generate_coerce_to_tgt_command(source_sid, source_detail)
        elif relationship in ["AllowedToAct", "AllowedToDelegate"]:
            return self._generate_delegation_command(relationship, source_detail, target_detail, source_sid, target_sid)

        if relationship.startswith('ADCSESC') or relationship in ('ManageCA', 'ManageCertificates', 'CoerceAndRelayNTLMToADCS'):
            return self._generate_adcs_command(relationship, source_user, target_user, source_sid, target_detail)

        if relationship in ('CoerceAndRelayToSMB', 'CoerceAndRelayNTLMToSMB'):
            return self._generate_smb_signing_check(target_detail, target_sid)
        if relationship in ('CoerceAndRelayToMSSQL', 'CoerceAndRelayToAdminService', 'CoerceAndRelayToADCS',
                            'CoerceAndRelayNTLMToLDAP', 'CoerceAndRelayNTLMToLDAPS'):
            return self._generate_relay_target_check(relationship, target_detail, target_sid)

        if relationship == 'LocalAdminRequired':
            return self._generate_local_admin_check(source_sid, target_sid)

        if target_type == 'GPO' and relationship in Config.ACL_RELATIONSHIPS and relationship not in ('GPLink', 'WriteGPLink'):
            return self.get_gpo_permissions_command(source_sid, target_detail)

        if target_type == 'OU' and relationship in Config.ACL_RELATIONSHIPS and relationship not in ('GPLink', 'WriteGPLink'):
            return self.get_ou_permissions_command(source_sid, target_detail)

        command_map = self._get_command_map(source_user, target_user, source_sid, target_sid)
        if relationship in command_map:
            return command_map[relationship]

        write_relationships = [
            'GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'AllExtendedRights',
            'WriteAccountRestrictions',
        ]

        if relationship in write_relationships and target_type in ['OU', 'GPO', 'COMPUTER', 'USER', 'GROUP']:
            return self._generate_acl_command(relationship, source_sid, target_detail, target_type)

        return self._generate_generic_command(relationship, source_sid, target_user, target_sid, target_dn)

    def _generate_dcsync_command(self, source_sid):
        return rf"""Import-Module ActiveDirectory
$source = Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties Name -EA 0
(Get-ADObject "{self.domain_dn}"{self.server_flag} -Properties nTSecurityDescriptor -EA 0).nTSecurityDescriptor.Access | Where-Object {{
    ($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -and
    ($_.ObjectType -in @('{Config.GUID_DS_REPL_GET_CHANGES_ALL}','{Config.GUID_DS_REPL_GET_CHANGES}')) -and
    ($null -ne $_.IdentityReference -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq "{source_sid}")
}} | Select-Object @{{Name='IdentityReference';Expression={{$source.Name}}}}, @{{Name='ActiveDirectoryRights';Expression={{
    switch($_.ObjectType) {{
        '{Config.GUID_DS_REPL_GET_CHANGES}' {{'DS-Replication-Get-Changes'}}
        '{Config.GUID_DS_REPL_GET_CHANGES_ALL}' {{'DS-Replication-Get-Changes-All'}}
    }}
}}}}"""

    def _generate_memberof_command(self, source_sid, target_user, target_sid):
        domain_users_sid = f"{self.domain_sid}-513"
        domain_computers_sid = f"{self.domain_sid}-515"
        authenticated_users_sid = "S-1-5-11"
        everyone_sid = "S-1-1-0"

        # these memberships are implicit in AD — no PS verification needed
        implicit_relationships = {
            (domain_users_sid, authenticated_users_sid): ("Domain Users", "Authenticated Users"),
            (domain_users_sid, everyone_sid): ("Domain Users", "Everyone"),
            (domain_computers_sid, authenticated_users_sid): ("Domain Computers", "Authenticated Users"),
            (domain_computers_sid, everyone_sid): ("Domain Computers", "Everyone"),
            (authenticated_users_sid, everyone_sid): ("Authenticated Users", "Everyone"),
        }

        if (source_sid, target_sid) in implicit_relationships:
            source_name, target_name = implicit_relationships[(source_sid, target_sid)]
            return f"# {source_name} is a member of {target_name} by default (inherited membership)"

        target_lookup = f"objectSID -eq '{target_sid}'"

        return rf"""Import-Module ActiveDirectory
$source = Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties memberOf,primaryGroupID,Name -EA 0
$target = Get-ADGroup -Filter {{{target_lookup}}}{self.server_flag} -Properties Name -EA 0

if ($target) {{
    $isMember = $source.memberOf -contains $target.DistinguishedName
    if (-not $isMember -and $source.primaryGroupID) {{
        $targetRID = ($target.SID.Value -split '-')[-1]
        $isMember = $source.primaryGroupID -eq [int]$targetRID
    }}
    if ($isMember) {{
        [PSCustomObject]@{{
            Member = $source.Name
            Group = $target.Name
            Status = "Member"
        }} | Format-Table -AutoSize
    }}
}}"""

    def _generate_coerce_to_tgt_command(self, source_sid, source_detail):
        source_type = ''
        if source_detail and isinstance(source_detail, dict):
            if 'type' in source_detail and source_detail['type']:
                source_type = source_detail['type'].upper()
            elif 'labels' in source_detail and isinstance(source_detail['labels'], list) and len(source_detail['labels']) > 0:
                source_type = source_detail['labels'][0].upper()

        if source_type == 'COMPUTER':
            return rf"""Import-Module ActiveDirectory
Get-ADComputer -Filter {{objectSID -eq '{source_sid}'}}{self.server_flag} -Properties TrustedForDelegation,TrustedToAuthForDelegation,'msDS-AllowedToDelegateTo' -EA 0 |
    ? {{$_.TrustedForDelegation -or $_.TrustedToAuthForDelegation -or $_.'msDS-AllowedToDelegateTo'}} |
    Select Name,TrustedForDelegation,TrustedToAuthForDelegation"""
        elif source_type == 'USER':
            return rf"""Import-Module ActiveDirectory
Get-ADUser -Filter {{objectSID -eq '{source_sid}'}}{self.server_flag} -Properties TrustedForDelegation,TrustedToAuthForDelegation,'msDS-AllowedToDelegateTo' -EA 0 |
    ? {{$_.TrustedForDelegation -or $_.TrustedToAuthForDelegation -or $_.'msDS-AllowedToDelegateTo'}} |
    Select Name,TrustedForDelegation,TrustedToAuthForDelegation"""
        else:
            return rf"""Import-Module ActiveDirectory
Get-ADObject -Filter {{objectSID -eq '{source_sid}'}}{self.server_flag} -Properties TrustedForDelegation,TrustedToAuthForDelegation,'msDS-AllowedToDelegateTo',ObjectClass -EA 0 |
    ? {{$_.TrustedForDelegation -or $_.TrustedToAuthForDelegation -or $_.'msDS-AllowedToDelegateTo'}} |
    Select @{{n='Type';e={{$_.ObjectClass}}}},Name,TrustedForDelegation,TrustedToAuthForDelegation"""

    def _generate_delegation_command(self, relationship, source_detail, target_detail, source_sid, target_sid):

        if relationship == "AllowedToAct":
            target_filter = f"objectSID -eq '{target_sid}'"

            return rf"""Import-Module ActiveDirectory
$source = Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties Name -EA 0
$target = Get-ADComputer -Filter {{{target_filter}}}{self.server_flag} -Properties msDS-AllowedToActOnBehalfOfOtherIdentity,Name -EA 0
if($target."msDS-AllowedToActOnBehalfOfOtherIdentity") {{
    $target."msDS-AllowedToActOnBehalfOfOtherIdentity".Access | Where-Object {{
        $null -ne $_.IdentityReference -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq "{source_sid}"
    }} | Select-Object @{{Name='IdentityReference';Expression={{$source.Name}}}}, @{{Name='ActiveDirectoryRights';Expression={{'AllowedToAct'}}}}
}}"""
        elif relationship == "AllowedToDelegate":
            source_filter = f"objectSID -eq '{source_sid}'"

            return rf"""Import-Module ActiveDirectory
$s = Get-ADObject -Filter {{{source_filter}}}{self.server_flag} -Properties "msDS-AllowedToDelegateTo",Name -EA 0
$s."msDS-AllowedToDelegateTo" | % {{
    "Source: $($s.Name)"
    "Target: $_"
    "Status: AllowedToDelegate"
    ""
}}"""

        return None

    def _generate_smb_signing_check(self, target_detail, target_sid):
        return rf"""Import-Module ActiveDirectory
$target = (Get-ADComputer -Filter {{objectSID -eq '{target_sid}'}}{self.server_flag} -Properties DNSHostName -EA 0).DNSHostName
Invoke-Command -ComputerName $target -ScriptBlock {{
    Get-SmbServerConfiguration | Select-Object RequireSecuritySignature
}}"""

    def _generate_relay_target_check(self, relationship, target_detail, target_sid):
        return rf"""Import-Module ActiveDirectory
Get-ADComputer -Filter {{objectSID -eq '{target_sid}'}}{self.server_flag} -Properties DNSHostName | Select-Object Name,DNSHostName"""

    def _generate_local_admin_check(self, source_sid, target_sid):
        # Same check as AdminTo — local Administrators group membership
        target_lookup = f"objectSID -eq '{target_sid}'"

        return rf"""Import-Module ActiveDirectory
$user = (Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties SamAccountName -EA 0).SamAccountName
$target = (Get-ADObject -Filter {{{target_lookup}}}{self.server_flag} -Properties DNSHostName -EA 0).DNSHostName

Invoke-Command -ComputerName $target -ScriptBlock {{
    net localgroup "Administrators"
}}

Write-Output ""
Write-Output "Look for '$user' or a group containing '$user' in the output above."
"""

    def _generate_adcs_command(self, relationship, source_user, target_user, source_sid, target_detail):

        preamble = rf"""Import-Module ActiveDirectory
$configDN = (Get-ADRootDSE{self.server_flag}).configurationNamingContext
$enrollOid = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
$autoEnrollOid = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
$templates = Get-ADObject -Filter {{objectClass -eq 'pKICertificateTemplate'}} -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configDN"{self.server_flag} -Properties Name,msPKI-Certificate-Name-Flag,msPKI-Enrollment-Flag,msPKI-RA-Signature,pKIExtendedKeyUsage,nTSecurityDescriptor,msPKI-Certificate-Application-Policy -EA 0
$cas = Get-ADObject -Filter {{objectClass -eq 'pKIEnrollmentService'}} -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configDN"{self.server_flag} -Properties Name,dNSHostName,certificateTemplates -EA 0
"""

        # Skips templates where only privileged groups can enroll
        enroll_check = rf"""
    $enrollAs = @()
    $t.nTSecurityDescriptor.Access | ForEach-Object {{
        $ot = $_.ObjectType.ToString()
        if (($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -and ($ot -eq $enrollOid -or $ot -eq $autoEnrollOid)) {{
            $enrollAs += $_.IdentityReference.ToString()
        }}
    }}
    $publishedOn = @()
    foreach ($ca in $cas) {{ if ($t.Name -in @($ca.certificateTemplates)) {{ $publishedOn += "$($ca.Name) ($($ca.dNSHostName))" }} }}
    if ($publishedOn.Count -eq 0) {{ continue }}
    $lowPriv = $false
    foreach ($e in $enrollAs) {{
        if ($e -match '-(513|515)$' -or $e -match '^S-1-(1-0|5-11)$' -or $e -match '(?i)(\\|^)(Everyone|Authenticated Users|Domain Users|Domain Computers)$') {{
            $lowPriv = $true; break
        }}
    }}
    if (-not $lowPriv) {{ continue }}
"""

        output_block = rf"""
    Write-Output "Template: $($t.Name)"
    Write-Output "  Can Enroll: $($enrollAs -join ', ')"
    Write-Output "  Published On: $($publishedOn -join ', ')"
"""

        # OIDs used across multiple checks
        any_purpose_oid = '2.5.29.37.0'
        client_auth_oid = '1.3.6.1.5.5.7.3.2'
        cert_req_agent_oid = '1.3.6.1.4.1.311.20.2.1'

        # Shared block: detect which other ESCs a template also matches (for notes)
        also_vuln_block = rf"""
    $also = @()
    $suppliesSubject = ([int]$t.'msPKI-Certificate-Name-Flag' -band 1) -eq 1
    $ekus = @($t.pKIExtendedKeyUsage)
    $hasClientAuth = '{client_auth_oid}' -in $ekus
    $hasAnyPurpose = '{any_purpose_oid}' -in $ekus -or $ekus.Count -eq 0
    $hasCRA = '{cert_req_agent_oid}' -in $ekus
    $managerApproval = ([int]$t.'msPKI-Enrollment-Flag' -band 2) -eq 2
    $raSignatures = [int]$t.'msPKI-RA-Signature'
    $noSecExt = ([int]$t.'msPKI-Enrollment-Flag' -band 0x80000) -ne 0
    $open = -not $managerApproval -and $raSignatures -eq 0
    if ($open -and $suppliesSubject -and $hasClientAuth) {{ $also += 'ESC1' }}
    if ($open -and $hasAnyPurpose) {{ $also += 'ESC2' }}
    if ($open -and $hasCRA) {{ $also += 'ESC3' }}
    if ($open -and $noSecExt -and $hasClientAuth) {{ $also += 'ESC9' }}
"""

        if relationship == 'ADCSESC1':
            return preamble + rf"""
$found = $false
foreach ($t in $templates) {{
    $suppliesSubject = ([int]$t.'msPKI-Certificate-Name-Flag' -band 1) -eq 1
    $ekus = @($t.pKIExtendedKeyUsage)
    $hasClientAuth = '{client_auth_oid}' -in $ekus
    $managerApproval = ([int]$t.'msPKI-Enrollment-Flag' -band 2) -eq 2
    $raSignatures = [int]$t.'msPKI-RA-Signature'
    if (-not ($suppliesSubject -and $hasClientAuth -and -not $managerApproval -and $raSignatures -eq 0)) {{ continue }}
{enroll_check}{also_vuln_block}{output_block}
    Write-Output "  Enrollee Supplies Subject: True"
    Write-Output "  Client Authentication EKU: True"
    Write-Output "  Manager Approval: False"
    Write-Output "  RESULT: Vulnerable to ESC1"
    $other = $also | Where-Object {{ $_ -ne 'ESC1' }}
    if ($other) {{ Write-Output "  NOTE: Also vulnerable to $($other -join ', ')" }}
    Write-Output ""
    $found = $true
}}
if (-not $found) {{ Write-Output "No ESC1 vulnerable templates found." }}
"""

        elif relationship == 'ADCSESC2':
            return preamble + rf"""
$found = $false
foreach ($t in $templates) {{
    $ekus = @($t.pKIExtendedKeyUsage)
    $hasAnyPurpose = '{any_purpose_oid}' -in $ekus -or $ekus.Count -eq 0
    $managerApproval = ([int]$t.'msPKI-Enrollment-Flag' -band 2) -eq 2
    $raSignatures = [int]$t.'msPKI-RA-Signature'
    if (-not ($hasAnyPurpose -and -not $managerApproval -and $raSignatures -eq 0)) {{ continue }}
{enroll_check}{also_vuln_block}{output_block}
    Write-Output "  Any Purpose / No EKU: True"
    Write-Output "  RESULT: Vulnerable to ESC2"
    $other = $also | Where-Object {{ $_ -ne 'ESC2' }}
    if ($other) {{ Write-Output "  NOTE: Also vulnerable to $($other -join ', ')" }}
    Write-Output ""
    $found = $true
}}
if (-not $found) {{ Write-Output "No ESC2 vulnerable templates found." }}
"""

        elif relationship == 'ADCSESC3':
            return preamble + rf"""
$found = $false
foreach ($t in $templates) {{
    $ekus = @($t.pKIExtendedKeyUsage)
    $hasCRA = '{cert_req_agent_oid}' -in $ekus
    $managerApproval = ([int]$t.'msPKI-Enrollment-Flag' -band 2) -eq 2
    $raSignatures = [int]$t.'msPKI-RA-Signature'
    if (-not ($hasCRA -and -not $managerApproval -and $raSignatures -eq 0)) {{ continue }}
{enroll_check}{also_vuln_block}{output_block}
    Write-Output "  Certificate Request Agent EKU: True"
    Write-Output "  RESULT: Vulnerable to ESC3"
    $other = $also | Where-Object {{ $_ -ne 'ESC3' }}
    if ($other) {{ Write-Output "  NOTE: Also vulnerable to $($other -join ', ')" }}
    Write-Output ""
    $found = $true
}}
if (-not $found) {{ Write-Output "No ESC3 vulnerable templates found." }}
"""

        elif relationship == 'ADCSESC4':
            return preamble + rf"""
$found = $false
foreach ($t in $templates) {{
    $publishedOn = @()
    foreach ($ca in $cas) {{ if ($t.Name -in @($ca.certificateTemplates)) {{ $publishedOn += "$($ca.Name) ($($ca.dNSHostName))" }} }}
    if ($publishedOn.Count -eq 0) {{ continue }}
    $writePerms = @()
    $t.nTSecurityDescriptor.Access | ForEach-Object {{
        $rights = $_.ActiveDirectoryRights.ToString()
        if ($rights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite|WriteProperty') {{
            $writePerms += "$($_.IdentityReference.ToString()) - $rights"
        }}
    }}
    if ($writePerms.Count -eq 0) {{ continue }}
{also_vuln_block}
    Write-Output "Template: $($t.Name)"
    Write-Output "  Published On: $($publishedOn -join ', ')"
    Write-Output "  Write Permissions:"
    $writePerms | ForEach-Object {{ Write-Output "    $_" }}
    Write-Output "  RESULT: Vulnerable to ESC4 (template ACL abuse)"
    $other = $also | Where-Object {{ $_ -ne 'ESC4' }}
    if ($other) {{ Write-Output "  NOTE: Also vulnerable to $($other -join ', ')" }}
    Write-Output ""
    $found = $true
}}
if (-not $found) {{ Write-Output "No ESC4 vulnerable templates found." }}
"""

        elif relationship in ('ADCSESC6a', 'ADCSESC6b'):
            return preamble + rf"""
# Check if any CA has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled
# This flag is stored in the CA's registry, check via certutil
Write-Output "Checking CA configuration for User-Specified SAN flag..."
Write-Output ""
foreach ($ca in $cas) {{
    Write-Output "CA: $($ca.Name) ($($ca.dNSHostName))"
    try {{
        $output = certutil -config "$($ca.dNSHostName)\$($ca.Name)" -getreg policy\EditFlags 2>&1
        if ($output -match 'EDITF_ATTRIBUTESUBJECTALTNAME2 -- 40000') {{
            Write-Output "  EDITF_ATTRIBUTESUBJECTALTNAME2: ENABLED"
            Write-Output "  RESULT: CA allows user-specified SAN (ESC6)"
        }} else {{
            Write-Output "  EDITF_ATTRIBUTESUBJECTALTNAME2: Disabled"
            Write-Output "  RESULT: Not vulnerable to ESC6"
        }}
    }} catch {{
        Write-Output "  Could not query CA configuration"
    }}
    Write-Output ""
}}
"""

        elif relationship == 'ADCSESC7':
            return preamble + rf"""
Write-Output "Checking CA permissions for ManageCA / ManageCertificates..."
Write-Output ""
foreach ($ca in $cas) {{
    Write-Output "CA: $($ca.Name) ($($ca.dNSHostName))"
    $ca_obj = Get-ADObject $ca.DistinguishedName{self.server_flag} -Properties nTSecurityDescriptor -EA 0
    if ($ca_obj) {{
        $ca_obj.nTSecurityDescriptor.Access | ForEach-Object {{
            $rights = $_.ActiveDirectoryRights.ToString()
            if ($rights -match 'GenericAll|WriteDacl|WriteOwner') {{
                Write-Output "  $($_.IdentityReference.ToString()) - $rights"
            }}
        }}
        Write-Output ""
        Write-Output "  To check ManageCA/ManageCertificates specifically, run:"
        Write-Output "    certutil -config `"$($ca.dNSHostName)\$($ca.Name)`" -getacl"
    }}
    Write-Output ""
}}
"""

        elif relationship in ('ADCSESC9a', 'ADCSESC9b'):
            return preamble + rf"""
$found = $false
foreach ($t in $templates) {{
    # CT_FLAG_NO_SECURITY_EXTENSION = 0x80000 on msPKI-Enrollment-Flag
    $noSecExt = ([int]$t.'msPKI-Enrollment-Flag' -band 0x80000) -ne 0
    $ekus = @($t.pKIExtendedKeyUsage)
    $hasClientAuth = '{client_auth_oid}' -in $ekus
    $managerApproval = ([int]$t.'msPKI-Enrollment-Flag' -band 2) -eq 2
    $raSignatures = [int]$t.'msPKI-RA-Signature'
    if (-not ($noSecExt -and $hasClientAuth -and -not $managerApproval -and $raSignatures -eq 0)) {{ continue }}
{enroll_check}{also_vuln_block}{output_block}
    Write-Output "  No Security Extension: True"
    Write-Output "  Client Authentication EKU: True"
    Write-Output "  RESULT: Vulnerable to ESC9 (no security extension)"
    $other = $also | Where-Object {{ $_ -ne 'ESC9' }}
    if ($other) {{ Write-Output "  NOTE: Also vulnerable to $($other -join ', ')" }}
    Write-Output ""
    $found = $true
}}
if (-not $found) {{ Write-Output "No ESC9 vulnerable templates found." }}
"""

        elif relationship in ('ADCSESC10a', 'ADCSESC10b'):
            return preamble + rf"""
# ESC10 relates to weak certificate mapping - must check registry on DCs
$dcs = Get-ADDomainController -Filter *{self.server_flag} -EA 0
if (-not $dcs) {{ $dcs = @(Get-ADDomainController{self.server_flag} -EA 0) }}

foreach ($dc in $dcs) {{
    Write-Output "DC: $($dc.HostName)"
    $regBlock = {{
        $result = @{{}}
        $scbe = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name 'StrongCertificateBindingEnforcement' -EA SilentlyContinue
        $result['SCBE'] = if ($scbe) {{ $scbe.StrongCertificateBindingEnforcement }} else {{ $null }}
        $cmm = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel' -Name 'CertificateMappingMethods' -EA SilentlyContinue
        $result['CMM'] = if ($cmm) {{ $cmm.CertificateMappingMethods }} else {{ $null }}
        $result
    }}
    try {{
        $vals = Invoke-Command -ComputerName $dc.HostName -ScriptBlock $regBlock -EA Stop
        if ($null -ne $vals['SCBE']) {{
            Write-Output "  StrongCertificateBindingEnforcement: $($vals['SCBE'])"
            if ($vals['SCBE'] -lt 2) {{
                Write-Output "  RESULT: Weak certificate mapping (value should be 2 for full enforcement)"
            }} else {{
                Write-Output "  RESULT: Strong certificate mapping enforced"
            }}
        }} else {{
            Write-Output "  StrongCertificateBindingEnforcement: Not set (defaults to 1, compatibility mode)"
            Write-Output "  RESULT: Weak certificate mapping (default allows bypass)"
        }}
        Write-Output ""
        if ($null -ne $vals['CMM']) {{
            Write-Output "  CertificateMappingMethods: $($vals['CMM'])"
            if ($vals['CMM'] -band 4) {{
                Write-Output "  RESULT: SAN mapping enabled (vulnerable)"
            }}
        }} else {{
            Write-Output "  CertificateMappingMethods: Not set (defaults include SAN mapping)"
            Write-Output "  RESULT: Default allows SAN-based mapping"
        }}
    }} catch {{
        Write-Output "  Could not connect to $($dc.HostName) to read registry."
        Write-Output "  Run on the DC: Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name StrongCertificateBindingEnforcement"
    }}
    Write-Output ""
}}
"""

        elif relationship in ('ManageCA', 'ManageCertificates'):
            return preamble + rf"""
Write-Output "Checking {relationship} permissions on {target_user}..."
Write-Output ""
foreach ($ca in $cas) {{
    if ($ca.Name -ne '{target_user}') {{ continue }}
    Write-Output "CA: $($ca.Name) ($($ca.dNSHostName))"
    $ca_obj = Get-ADObject $ca.DistinguishedName{self.server_flag} -Properties nTSecurityDescriptor -EA 0
    if ($ca_obj) {{
        $ca_obj.nTSecurityDescriptor.Access | ForEach-Object {{
            $rights = $_.ActiveDirectoryRights.ToString()
            if ($rights -match 'GenericAll|WriteDacl|WriteOwner') {{
                Write-Output "  $($_.IdentityReference.ToString()) - $rights"
            }}
        }}
    }}
    Write-Output ""
    Write-Output "Run for detailed CA ACL:"
    Write-Output "  certutil -config `"$($ca.dNSHostName)\$($ca.Name)`" -getacl"
    Write-Output ""
}}
"""

        elif relationship in ('CoerceAndRelayNTLMToADCS', 'ADCSESC8'):
            return preamble + self._esc8_web_enrollment_block()

        # Fallback for ADCSESC5, ADCSESC11, ADCSESC12, ADCSESC13
        else:
            return preamble + rf"""
Write-Output "Checking AD CS configuration for {relationship}..."
Write-Output ""
foreach ($ca in $cas) {{
    Write-Output "CA: $($ca.Name) ($($ca.dNSHostName))"
    Write-Output "  Published Templates: $(@($ca.certificateTemplates).Count)"
    $ca_obj = Get-ADObject $ca.DistinguishedName{self.server_flag} -Properties nTSecurityDescriptor -EA 0
    if ($ca_obj) {{
        Write-Output "  Permissions:"
        $ca_obj.nTSecurityDescriptor.Access | ForEach-Object {{
            $rights = $_.ActiveDirectoryRights.ToString()
            if ($rights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite|WriteProperty|ExtendedRight') {{
                Write-Output "    $($_.IdentityReference.ToString()) - $rights"
            }}
        }}
    }}
    Write-Output ""
}}
"""

    def _esc8_web_enrollment_block(self):
        return rf"""
$checkBlock = {{
    Import-Module WebAdministration -EA Stop
    $certSrv = Get-WebApplication -Site "Default Web Site" -Name "CertSrv" -EA SilentlyContinue
    if (-not $certSrv) {{
        Write-Output "  Web Enrollment: Not installed"
        Write-Output "  RESULT: Not vulnerable to ESC8 (web enrollment not enabled)"
        return
    }}
    Write-Output "  Web Enrollment: Installed"
    $bindings = Get-WebBinding -Name "Default Web Site" -EA SilentlyContinue
    $hasHttp = ($bindings | Where-Object {{ $_.protocol -eq 'http' }}).Count -gt 0
    $hasHttps = ($bindings | Where-Object {{ $_.protocol -eq 'https' }}).Count -gt 0
    if ($hasHttp) {{ Write-Output "  HTTP (port 80): Enabled" }} else {{ Write-Output "  HTTP (port 80): Disabled" }}
    if ($hasHttps) {{ Write-Output "  HTTPS: Enabled" }}
    $epa = Get-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\CertSrv" -Filter "system.webServer/security/authentication/windowsAuthentication/extendedProtection" -Name tokenChecking -EA SilentlyContinue
    $epaVal = if ($epa -and $epa.Value -and $epa.Value -ne 'None') {{ $epa.Value }} else {{ 'Disabled' }}
    Write-Output "  EPA (Extended Protection): $epaVal"
    Write-Output ""
    if ($hasHttp -and $epaVal -eq 'Disabled') {{
        Write-Output "  RESULT: Vulnerable to ESC8 - HTTP web enrollment enabled with no EPA"
    }} elseif ($hasHttp) {{
        Write-Output "  RESULT: HTTP enabled but EPA is active - relay may be blocked"
    }} else {{
        Write-Output "  RESULT: No HTTP binding - NTLM relay to web enrollment not possible"
    }}
}}

foreach ($ca in $cas) {{
    Write-Output "CA: $($ca.Name) ($($ca.dNSHostName))"
    Write-Output ""
    try {{
        Invoke-Command -ComputerName $ca.dNSHostName -ScriptBlock $checkBlock -EA Stop
    }} catch {{
        if ($env:COMPUTERNAME -eq $ca.dNSHostName.Split('.')[0]) {{
            & $checkBlock
        }} else {{
            Write-Output "  Could not connect to $($ca.dNSHostName) to check IIS."
            Write-Output "  Run the following on the CA server:"
            Write-Output "    Import-Module WebAdministration"
            Write-Output "    Get-WebApplication -Site 'Default Web Site' -Name 'CertSrv'"
            Write-Output "    Get-WebBinding -Name 'Default Web Site'"
        }}
    }}
    Write-Output ""
}}
"""

    def _generate_acl_command(self, relationship, source_sid, target_detail, target_type):
        target_dn = target_detail.get('dn') if target_detail else None
        target_name = target_detail.get('name') if target_detail else 'Unknown'

        target_sid = None
        if target_detail and isinstance(target_detail, dict):
            raw_sid = target_detail.get('sid') or target_detail.get('objectid')
            if raw_sid:
                if '-S-1-' in raw_sid and not raw_sid.startswith('S-1-'):
                    idx = raw_sid.rfind('-S-1-')
                    if idx > 0:
                        target_sid = 'S-1' + raw_sid[idx + 4:]
                else:
                    target_sid = raw_sid

        if target_type == 'OU' and target_dn:
            return f"""Import-Module ActiveDirectory
$source = Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties Name -EA 0
$target = Get-ADObject -Identity "{target_dn}"{self.server_flag} -Properties nTSecurityDescriptor -EA 0
$target.nTSecurityDescriptor.Access | Where-Object {{
    $null -ne $_.IdentityReference -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq "{source_sid}"
}} | Select-Object @{{Name='Source';Expression={{$source.Name}}}}, @{{Name='Target';Expression={{$target.Name}}}}, ActiveDirectoryRights"""

        elif target_type == 'GPO':
            gpo_guid = None
            if target_detail and 'dn' in target_detail:
                guid_match = re.search(r'CN=\{([0-9A-F-]+)\}', target_detail['dn'], re.IGNORECASE)
                if guid_match:
                    gpo_guid = guid_match.group(1)

            if gpo_guid:
                return f"""Import-Module ActiveDirectory
$source = Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties Name -EA 0
$target = Get-ADObject "CN={{{gpo_guid}}},CN=Policies,CN=System,$((Get-ADDomain{self.server_flag}).DistinguishedName)"{self.server_flag} -Properties nTSecurityDescriptor,DisplayName -EA 0
$target.nTSecurityDescriptor.Access | Where-Object {{
    $null -ne $_.IdentityReference -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq "{source_sid}"
}} | Select-Object @{{Name='Source';Expression={{$source.Name}}}}, @{{Name='Target';Expression={{$target.DisplayName}}}}, ActiveDirectoryRights"""

        elif target_type in ['COMPUTER', 'USER', 'GROUP']:
            cmdlet = f"Get-AD{target_type.title()}"

            return f"""Import-Module ActiveDirectory
$source = Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties Name -EA 0
$target = {cmdlet} -Filter {{objectSID -eq "{target_sid if target_sid else ""}"}} -Properties nTSecurityDescriptor{self.server_flag} -EA 0
$target.nTSecurityDescriptor.Access | Where-Object {{
    $null -ne $_.IdentityReference -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq "{source_sid}"
}} | Select-Object @{{Name='Source';Expression={{$source.Name}}}}, @{{Name='Target';Expression={{$target.Name}}}}, ActiveDirectoryRights"""

        else:
            target_filter = f'objectSID -eq "{target_sid}"'
            return f"""Import-Module ActiveDirectory
$source = Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties Name -EA 0
$target = Get-ADObject -Filter {{{target_filter}}}{self.server_flag} -Properties nTSecurityDescriptor -EA 0
$target.nTSecurityDescriptor.Access | Where-Object {{
    $null -ne $_.IdentityReference -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq "{source_sid}"
}} | Select-Object @{{Name='Source';Expression={{$source.Name}}}}, @{{Name='Target';Expression={{$target.Name}}}}, ActiveDirectoryRights"""

    def _get_command_map(self, source_user, target_user, source_sid, target_sid):
        target_lookup = f"objectSID -eq '{target_sid}'"

        return {
            "AddMember": rf"""Import-Module ActiveDirectory
$source = Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties Name -EA 0
$t = Get-ADObject -Filter {{{target_lookup}}}{self.server_flag} -Properties nTSecurityDescriptor
$t.nTSecurityDescriptor.Access | ? {{
    $null -ne $_.IdentityReference -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq "{source_sid}" -and
    (($_.ActiveDirectoryRights -match 'WriteProperty' -and $_.ObjectType -eq '{Config.GUID_MEMBER_ATTR}') -or
     $_.ActiveDirectoryRights -match 'GenericWrite|GenericAll')
}} | Select-Object @{{Name='Source';Expression={{$source.Name}}}}, @{{Name='Target';Expression={{$t.Name}}}}, ActiveDirectoryRights""",

            "AddSelf": rf"""Import-Module ActiveDirectory
$source = Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties Name -EA 0
$t = Get-ADObject -Filter {{{target_lookup}}}{self.server_flag} -Properties nTSecurityDescriptor
$t.nTSecurityDescriptor.Access | ? {{
    $null -ne $_.IdentityReference -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq "{source_sid}" -and
    $_.ActiveDirectoryRights -match "Self"
}} | Select-Object @{{Name='Source';Expression={{$source.Name}}}}, @{{Name='Target';Expression={{$t.Name}}}}, ActiveDirectoryRights""",

            "DumpSMSAPassword": rf"""Import-Module ActiveDirectory
$msa = Get-ADObject -Filter {{{target_lookup} -and objectClass -eq "msDS-ManagedServiceAccount"}}{self.server_flag} -Properties "msDS-ManagedPasswordPrincipals"
if ($msa -and $msa."msDS-ManagedPasswordPrincipals") {{
    $msa."msDS-ManagedPasswordPrincipals" | % {{
        $principal = Get-ADObject $_{self.server_flag} -Properties objectSID -ErrorAction SilentlyContinue
        if ($principal -and $principal.objectSID.Value -eq "{source_sid}") {{
            [PSCustomObject]@{{ServiceAccount=$msa.Name;Principal=$principal.Name}}
        }}
    }}
}}""",

            "GPLink": rf"""Import-Module ActiveDirectory
$source = Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties DistinguishedName -EA 0
$target = Get-ADObject -Filter {{{target_lookup}}}{self.server_flag} -Properties gpLink -EA 0
if ($target.gpLink -and $source) {{
    $sourceDN = $source.DistinguishedName
    if ($target.gpLink -match [regex]::Escape($sourceDN)) {{
        [PSCustomObject]@{{GPO=$source.Name;LinkedTo=$target.DistinguishedName;Status="Linked"}}
    }}
}}""",

            "Owns": rf"""Import-Module ActiveDirectory
$source = Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties Name -EA 0
$t = Get-ADObject -Filter {{{target_lookup}}}{self.server_flag} -Properties nTSecurityDescriptor
$ownerSid = $t.nTSecurityDescriptor.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
if ($ownerSid -eq "{source_sid}") {{
    [PSCustomObject]@{{Source=$source.Name;Owner=$t.nTSecurityDescriptor.Owner;Target=$t.Name;Via='Direct'}}
}} else {{
    $grp = Get-ADGroup -Filter {{SID -eq $ownerSid}}{self.server_flag} -EA 0
    if ($grp) {{
        $m = Get-ADGroupMember $grp -Recursive{self.server_flag} -EA 0 | Where-Object {{ $_.SID.Value -eq "{source_sid}" }} | Select-Object -First 1
        if ($m) {{ [PSCustomObject]@{{Source=$source.Name;Owner=$t.nTSecurityDescriptor.Owner;Target=$t.Name;Via='Group membership'}} }}
    }}
}}""",

            "ReadGMSAPassword": rf"""Import-Module ActiveDirectory
$gmsa = Get-ADServiceAccount -Filter {{{target_lookup}}}{self.server_flag} -Properties PrincipalsAllowedToRetrieveManagedPassword -ErrorAction SilentlyContinue
if ($gmsa -and $gmsa.PrincipalsAllowedToRetrieveManagedPassword) {{
    $gmsa.PrincipalsAllowedToRetrieveManagedPassword | % {{
        $principal = Get-ADObject $_{self.server_flag} -Properties objectSID -ErrorAction SilentlyContinue
        if ($principal -and $principal.objectSID.Value -eq "{source_sid}") {{
            [PSCustomObject]@{{ServiceAccount=$gmsa.Name;Principal=$principal.Name}}
        }}
    }}
}}""",

            "ReadLAPSPassword": rf"""Import-Module ActiveDirectory
$source = Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties Name -EA 0
$target = Get-ADObject -Filter {{{target_lookup}}}{self.server_flag} -Properties nTSecurityDescriptor,Name -EA 0

$permissions = $target.nTSecurityDescriptor.Access | Where-Object {{
    $sidMatch = try {{ $null -ne $_.IdentityReference -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq "{source_sid}" }} catch {{ $false }}
    $readProperty = $_.ActiveDirectoryRights -match 'ReadProperty'
    $lapsObjects = $_.ObjectType -in @('{Config.GUID_LAPS_PASSWORD}','{Config.GUID_LAPS_EXPIRATION}')
    $sidMatch -and $readProperty -and $lapsObjects
}}

if($permissions) {{
    $permissions | Select-Object @{{Name='IdentityReference';Expression={{$source.Name}}}}, @{{Name='Target';Expression={{$target.Name}}}}, @{{Name='ActiveDirectoryRights';Expression={{'ReadProperty'}}}}, @{{Name='ObjectType';Expression={{
        switch($_.ObjectType) {{
            '{Config.GUID_LAPS_PASSWORD}' {{ 'ms-Mcs-AdmPwd (LAPS Password)' }}
            '{Config.GUID_LAPS_EXPIRATION}' {{ 'ms-Mcs-AdmPwdExpirationTime (LAPS Expiration)' }}
        }}
    }}}} | Format-Table -AutoSize
}}""",

            "SyncLAPSPassword": rf"""Import-Module ActiveDirectory
$source = Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties Name -EA 0
$t = Get-ADObject -Filter {{{target_lookup}}}{self.server_flag} -Properties nTSecurityDescriptor
$t.nTSecurityDescriptor.Access | ? {{
    $null -ne $_.IdentityReference -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq "{source_sid}" -and
    $_.ActiveDirectoryRights -match 'WriteProperty' -and
    $_.ObjectType -eq '{Config.GUID_LAPS_PASSWORD}'
}} | Select-Object @{{Name='Source';Expression={{$source.Name}}}}, @{{Name='Target';Expression={{$t.Name}}}}, ActiveDirectoryRights""",

            "WriteGPLink": rf"""Import-Module ActiveDirectory
$source = Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties Name -EA 0
$t = Get-ADObject -Filter {{{target_lookup}}}{self.server_flag} -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue
if ($t) {{
    $t.nTSecurityDescriptor.Access | ? {{
        $null -ne $_.IdentityReference -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq "{source_sid}" -and
        (($_.ActiveDirectoryRights -match 'WriteProperty' -and $_.ObjectType -eq '{Config.GUID_GPLINK_ATTR}') -or
         $_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner')
    }} | Select-Object @{{Name='Source';Expression={{$source.Name}}}}, @{{Name='Target';Expression={{$t.Name}}}}, ActiveDirectoryRights
}} else {{
    Write-Output "Target object not found"
}}""",

            "WriteSPN": rf"""Import-Module ActiveDirectory
$source = Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties Name -EA 0
$t = Get-ADObject -Filter {{{target_lookup}}}{self.server_flag} -Properties nTSecurityDescriptor
$t.nTSecurityDescriptor.Access | ? {{
    $null -ne $_.IdentityReference -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq "{source_sid}" -and
    $_.ActiveDirectoryRights -match 'WriteProperty' -and
    $_.ObjectType -eq '{Config.GUID_SPN_ATTR}'
}} | Select-Object @{{Name='Source';Expression={{$source.Name}}}}, @{{Name='Target';Expression={{$t.Name}}}}, ActiveDirectoryRights""",

            "CanRDP": rf"""Import-Module ActiveDirectory
$user = (Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties SamAccountName -EA 0).SamAccountName
$target = (Get-ADObject -Filter {{{target_lookup}}}{self.server_flag} -Properties DNSHostName -EA 0).DNSHostName

Invoke-Command -ComputerName $target -ScriptBlock {{
    net localgroup "Remote Desktop Users"
}}

Write-Output ""
Write-Output "Look for '$user' or a group containing '$user' in the output above."
""",

            "CanPSRemote": rf"""Import-Module ActiveDirectory
$user = (Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties SamAccountName -EA 0).SamAccountName
$target = (Get-ADObject -Filter {{{target_lookup}}}{self.server_flag} -Properties DNSHostName -EA 0).DNSHostName

Invoke-Command -ComputerName $target -ScriptBlock {{
    net localgroup "Remote Management Users"
}}

Write-Output ""
Write-Output "Look for '$user' or a group containing '$user' in the output above."
""",

            "ExecuteDCOM": rf"""Import-Module ActiveDirectory
$user = (Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties SamAccountName -EA 0).SamAccountName
$target = (Get-ADObject -Filter {{{target_lookup}}}{self.server_flag} -Properties DNSHostName -EA 0).DNSHostName

Invoke-Command -ComputerName $target -ScriptBlock {{
    net localgroup "Distributed COM Users"
}}

Write-Output ""
Write-Output "Look for '$user' or a group containing '$user' in the output above."
""",

            "AddKeyCredential": rf"""Import-Module ActiveDirectory
$source = Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties Name -EA 0
$t = Get-ADObject -Filter {{{target_lookup}}}{self.server_flag} -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue
if ($t) {{
    $t.nTSecurityDescriptor.Access | ? {{
        $null -ne $_.IdentityReference -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq "{source_sid}" -and
        $_.ActiveDirectoryRights -match 'WriteProperty' -and
        $_.ObjectType -eq '{Config.GUID_KEY_CREDENTIAL_LINK}'
    }} | Select-Object @{{Name='Source';Expression={{$source.Name}}}}, @{{Name='Target';Expression={{$t.Name}}}}, ActiveDirectoryRights
}} else {{
    Write-Output "Target object not found"
}}""",

            "AddKeyCredentialLink": rf"""Import-Module ActiveDirectory
$source = Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties Name -EA 0
$t = Get-ADObject -Filter {{{target_lookup}}}{self.server_flag} -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue
if ($t) {{
    $t.nTSecurityDescriptor.Access | ? {{
        $null -ne $_.IdentityReference -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq "{source_sid}" -and
        $_.ActiveDirectoryRights -match 'WriteProperty' -and
        $_.ObjectType -eq '{Config.GUID_KEY_CREDENTIAL_LINK}'
    }} | Select-Object @{{Name='Source';Expression={{$source.Name}}}}, @{{Name='Target';Expression={{$t.Name}}}}, ActiveDirectoryRights
}} else {{
    Write-Output "Target object not found"
}}""",

            "ForceChangePassword": rf"""Import-Module ActiveDirectory
$source = Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties Name -EA 0
$t = Get-ADObject -Filter {{{target_lookup}}}{self.server_flag} -Properties nTSecurityDescriptor
$t.nTSecurityDescriptor.Access | ? {{
    $null -ne $_.IdentityReference -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq "{source_sid}" -and
    $_.ActiveDirectoryRights -match "ExtendedRight" -and
    $_.ObjectType -eq "{Config.GUID_FORCE_CHANGE_PASSWORD}"
}} | Select-Object @{{Name='Source';Expression={{$source.Name}}}}, @{{Name='Target';Expression={{$t.Name}}}}, ActiveDirectoryRights""",

            "ChangePassword": rf"""Import-Module ActiveDirectory
$source = Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties Name -EA 0
$t = Get-ADObject -Filter {{{target_lookup}}}{self.server_flag} -Properties nTSecurityDescriptor
$t.nTSecurityDescriptor.Access | ? {{
    $null -ne $_.IdentityReference -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq "{source_sid}" -and
    $_.ActiveDirectoryRights -match "ExtendedRight" -and
    $_.ObjectType -eq "{Config.GUID_USER_CHANGE_PASSWORD}"
}} | Select-Object @{{Name='Source';Expression={{$source.Name}}}}, @{{Name='Target';Expression={{$t.Name}}}}, ActiveDirectoryRights""",

            "WriteAccountRestrictions": rf"""Import-Module ActiveDirectory
$source = Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties Name -EA 0
$t = Get-ADObject -Filter {{{target_lookup}}}{self.server_flag} -Properties nTSecurityDescriptor
$t.nTSecurityDescriptor.Access | ? {{
    $null -ne $_.IdentityReference -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq "{source_sid}" -and
    $_.ActiveDirectoryRights -match 'WriteProperty' -and
    $_.ObjectType -eq '{Config.GUID_ACCOUNT_RESTRICTIONS}'
}} | Select-Object @{{Name='Source';Expression={{$source.Name}}}}, @{{Name='Target';Expression={{$t.Name}}}}, ActiveDirectoryRights""",

            "AdminTo": rf"""Import-Module ActiveDirectory
$user = (Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties SamAccountName -EA 0).SamAccountName
$target = (Get-ADObject -Filter {{{target_lookup}}}{self.server_flag} -Properties DNSHostName -EA 0).DNSHostName

Invoke-Command -ComputerName $target -ScriptBlock {{
    net localgroup "Administrators"
}}

Write-Output ""
Write-Output "Look for '$user' or a group containing '$user' in the output above."
""",

            "HasSession": rf"""Import-Module ActiveDirectory
# Sessions are ephemeral - this confirms the user and computer exist, then checks for an active session
$user = Get-ADUser -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties SamAccountName,Enabled,LastLogonDate -EA 0
$target = Get-ADComputer -Filter {{{target_lookup}}}{self.server_flag} -Properties Name,DNSHostName -EA 0
if ($user -and $target) {{
    Write-Output "User: $($user.SamAccountName)"
    Write-Output "Enabled: $($user.Enabled)"
    Write-Output "Last Logon: $($user.LastLogonDate)"
    Write-Output "Computer: $($target.Name)"
    Write-Output "DNS: $($target.DNSHostName)"
    Write-Output ""
    Write-Output ""
    Write-Output "To check for active sessions, run this on $($target.DNSHostName) with admin access:"
    Write-Output "  query user"
}}""",

            "SQLAdmin": rf"""Import-Module ActiveDirectory
$source = Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties SamAccountName,Name -EA 0
$target = Get-ADComputer -Filter {{{target_lookup}}}{self.server_flag} -Properties servicePrincipalName,DNSHostName,Name -EA 0
if ($target) {{
    Write-Output "Source: $($source.Name)"
    Write-Output "Target: $($target.Name) ($($target.DNSHostName))"
    $sqlSpns = $target.servicePrincipalName | Where-Object {{ $_ -match '^MSSQLSvc/' }}
    if ($sqlSpns) {{
        Write-Output ""
        Write-Output "SQL Server SPNs:"
        $sqlSpns | ForEach-Object {{ Write-Output "  $_" }}
    }}
    Write-Output ""
    Write-Output "To confirm sysadmin role membership, connect to the SQL instance on $($target.DNSHostName) and run:"
    Write-Output "  SELECT name, type_desc, IS_SRVROLEMEMBER('sysadmin', name) AS is_sysadmin"
    Write-Output "  FROM sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1"
}}""",

            "Contains": rf"""Import-Module ActiveDirectory
# Verify the containment relationship - child object sits inside the parent
$parent = Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties DistinguishedName,Name -EA 0
$child = Get-ADObject -Filter {{{target_lookup}}}{self.server_flag} -Properties DistinguishedName,Name -EA 0
if ($parent -and $child) {{
    if ($child.DistinguishedName -match [regex]::Escape($parent.DistinguishedName)) {{
        Write-Output "Parent: $($parent.DistinguishedName)"
        Write-Output "Child: $($child.DistinguishedName)"
        Write-Output "Contains: Yes"
    }}
}}"""
        }

    def get_gpo_permissions_command(self, source_sid, target_detail):
        gpo_guid = None
        if target_detail:
            dn = target_detail.get('dn', '')
            if isinstance(dn, str):
                guid_match = re.search(r'CN=\{([0-9A-F-]+)\}', dn, re.IGNORECASE)
                if guid_match:
                    gpo_guid = guid_match.group(1)

            if not gpo_guid:
                name = target_detail.get('name', '')
                if isinstance(name, str) and name.startswith('{') and name.endswith('}'):
                    gpo_guid = name[1:-1]  # Remove { and }

        if gpo_guid:
            return rf"""# Check permissions on specific GPO
Import-Module ActiveDirectory
$source = Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties Name -EA 0
$gpoPath = "CN={{{gpo_guid}}},CN=Policies,CN=System,$((Get-ADDomain{self.server_flag}).DistinguishedName)"
$gpo = Get-ADObject -Identity $gpoPath{self.server_flag} -Properties nTSecurityDescriptor, displayName -ErrorAction SilentlyContinue
if ($gpo) {{
    $gpo.nTSecurityDescriptor.Access | Where-Object {{
        $null -ne $_.IdentityReference -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq "{source_sid}"
    }} | Select-Object @{{Name='Source';Expression={{$source.Name}}}}, @{{Name='Target';Expression={{$gpo.displayName}}}}, ActiveDirectoryRights
}}
else {{
    Write-Output "GPO with GUID {gpo_guid} not found"
}}"""
        else:
            # Generic GPO search when GUID is not available
            target_name = target_detail.get('name', 'UnknownGPO') if target_detail else 'UnknownGPO'
            return rf"""# Search for GPOs with permissions for the source
Import-Module ActiveDirectory
$source = Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties Name -EA 0
$gpos = Get-ADObject -SearchBase "CN=Policies,CN=System,$((Get-ADDomain{self.server_flag}).DistinguishedName)" -Filter {{objectClass -eq "groupPolicyContainer"}} -Properties displayName, nTSecurityDescriptor{self.server_flag}

$gpos | ForEach-Object {{
    $gpo = $_
    $perms = $gpo.nTSecurityDescriptor.Access | Where-Object {{
        $null -ne $_.IdentityReference -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq "{source_sid}"
    }}

    if ($perms) {{
        $perms | Select-Object @{{Name='Source';Expression={{$source.Name}}}}, @{{Name='Target';Expression={{$gpo.displayName}}}}, ActiveDirectoryRights
    }}
}}"""

    def get_ou_permissions_command(self, source_sid, target_detail):
            ou_dn = None
            if target_detail:
                ou_dn = target_detail.get('dn')
                if not ou_dn:
                    ou_name = target_detail.get('name')
                    if ou_name:
                        # Construct basic OU DN
                        ou_dn = f"OU={ou_name}"

            return f"""Import-Module ActiveDirectory
$source = Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties Name -EA 0
$target = Get-ADObject "{ou_dn or 'OU=UNKNOWN'}"{self.server_flag} -Properties nTSecurityDescriptor -EA 0
$target.nTSecurityDescriptor.Access | Where-Object {{
    $null -ne $_.IdentityReference -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq "{source_sid}"
}} | Select-Object @{{Name='Source';Expression={{$source.Name}}}}, @{{Name='Target';Expression={{$target.Name}}}}, ActiveDirectoryRights"""

    def _generate_generic_command(self, relationship, source_sid, target_user, target_sid, target_dn):
        if target_dn:
            return f"""Import-Module ActiveDirectory
$source = Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties Name -EA 0
$target = Get-ADObject -Identity "{target_dn}"{self.server_flag} -Properties nTSecurityDescriptor -EA 0
$target.nTSecurityDescriptor.Access | Where-Object {{
    $null -ne $_.IdentityReference -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq "{source_sid}"
}} | Select-Object @{{Name='Source';Expression={{$source.Name}}}}, @{{Name='Target';Expression={{$target.Name}}}}, ActiveDirectoryRights"""

        target_filter = f'objectSID -eq "{target_sid}"'

        return f"""Import-Module ActiveDirectory
$source = Get-ADObject -Filter {{objectSID -eq "{source_sid}"}}{self.server_flag} -Properties Name -EA 0
$target = Get-ADObject -Filter {{{target_filter}}}{self.server_flag} -Properties nTSecurityDescriptor -EA 0
$target.nTSecurityDescriptor.Access | Where-Object {{
    $null -ne $_.IdentityReference -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq "{source_sid}"
}} | Select-Object @{{Name='Source';Expression={{$source.Name}}}}, @{{Name='Target';Expression={{$target.Name}}}}, ActiveDirectoryRights"""
