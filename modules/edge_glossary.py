EDGE_GLOSSARY = {
    "MemberOf": {
        "description": "This account belongs to the target group and inherits all of its permissions.",
        "risk": "Any permissions the group has, including admin access, are automatically granted to every member.",
        "mitigation": "Review membership of the group regularly, especially if it grants administrative or sensitive rights, and remove any accounts that no longer require it. Consider whether group nesting is needed, since nested groups obscure who ultimately holds the access. Legitimate members (service accounts, role-based groups) should be documented and reviewed against your access management policy."
    },
    "AddMember": {
        "description": "This account can add new members to the target group.",
        "risk": "A compromised account could be added to a privileged group, instantly granting elevated access.",
        "mitigation": "Restrict the right to add members to privileged groups to dedicated administrators. Self-service provisioning tools or helpdesk systems may legitimately hold this right, but they should be scoped to non-privileged groups only. Audit the principals that can modify each privileged group and log membership changes so unauthorised additions can be detected promptly."
    },
    "AddSelf": {
        "description": "This account can add itself to the target group without approval.",
        "risk": "A compromised account can self-promote into a privileged group and immediately gain its access rights.",
        "mitigation": "Remove the Self right from the group's access list so that accounts cannot add themselves. Privileged groups should rely on AdminSDHolder to protect their permissions from drift. Where self-service group joining is required (for example, distribution lists or project teams), restrict it to non-privileged groups only."
    },
    "GenericAll": {
        "description": "This account has full control over the target, including read, write, and modify on all attributes.",
        "risk": "Allows password resets, security changes, or enabling delegation, which leads to complete takeover of the target.",
        "mitigation": "Remove GenericAll from non-admin principals where possible. Replace it with the minimum specific rights needed, for example ForceChangePassword for helpdesk password resets, rather than full control. Helpdesk teams and service accounts may have legitimate broad rights, so document these, audit the list, and monitor for changes.",
        "mitigation_overrides": {
            "gpo": "Remove GenericAll on this Group Policy from non-administrative principals. Edit rights on a Group Policy let an attacker change scripts, software deployments, and security settings pushed to every system the policy applies to, so they should sit with a small documented administrative group. Audit who can edit each policy, particularly policies linked to the domain root or privileged organisational units, and log changes to the policy's contents so unauthorised modifications are detected promptly.",
            "ou": "Remove GenericAll on this organisational unit from non-administrative principals. Permissions on an OU cascade to every account and computer below it through inheritance, so the blast radius is the entire subtree. Where administrative access is genuinely required, delegate the specific right needed (for example, password reset on user objects) at the OU rather than full control, and review delegated permissions regularly.",
            "container": "Remove GenericAll on this container from non-administrative principals. Permissions on a container are inherited by every object inside it, so this right effectively grants control over all child accounts and computers. Default containers (such as Users and Computers) cannot block inheritance the way an organisational unit can, so over-broad permissions here need particular care.",
            "enterpriseca": "Remove GenericAll on this Certificate Authority from non-administrative principals. Control of the CA allows certificates to be issued or approved that authenticate as any account in the domain, including Domain Admins, and that access survives password changes. CA management rights should sit with a small dedicated PKI administrative group, and changes to the CA configuration should be logged and reviewed.",
            "certtemplate": "Remove GenericAll on this certificate template from non-administrative principals. Edit rights on a template allow it to be reconfigured to issue login certificates for any account, which is a common route to Domain Admin. Template ACLs should be limited to PKI administrators and changes monitored.",
            "domain": "Remove GenericAll on the domain object from any account other than Domain or Enterprise Admins. Permissions at the domain root affect every object in the directory and grant the ability to add domain-wide rights such as DCSync, which leads to full domain compromise. Treat any non-administrative principal with this right as a critical finding."
        }
    },
    "WriteDacl": {
        "description": "This account can change who has access to the target by editing its permissions.",
        "risk": "An attacker can grant themselves full control over the target by modifying its access list.",
        "mitigation": "Remove the right to modify access controls on sensitive objects from any account that does not need it. Backup or identity management products may legitimately hold this right on specific objects; these should be documented, limited in scope, and monitored for changes. Enabling auditing on the object's access list helps detect unauthorised modifications.",
        "mitigation_overrides": {
            "gpo": "Remove the right to modify the access list of this Group Policy from any non-administrative principal. An attacker who can rewrite the ACL can grant themselves edit rights and push code or settings to every linked system. Group Policy ACL changes should be limited to a small administrative group and audited.",
            "ou": "Remove the right to modify the access list of this organisational unit from non-administrative principals. ACL changes here cascade through inheritance and let an attacker grant themselves control of every account and computer in the OU. Enable auditing on the OU's access list so modifications are detected.",
            "container": "Remove the right to modify the access list of this container from non-administrative principals. ACL changes are inherited by every child object, so this right leads to full control of the contents of the container.",
            "enterpriseca": "Remove the right to modify the access list on this Certificate Authority from non-administrative principals. The ability to rewrite the CA's ACL leads to full CA control and the ability to issue trusted login certificates for any account. Restrict to dedicated PKI administrators and log changes.",
            "certtemplate": "Remove the right to modify the access list on this certificate template from non-administrative principals. The ability to rewrite the ACL allows enrolment rights to be granted to attacker-controlled accounts, which can then request login certificates for privileged accounts.",
            "domain": "Remove the right to modify the access list on the domain object from any non-administrative principal. ACL changes at the domain root grant the ability to add DCSync or other domain-wide privileges, leading to full domain compromise."
        }
    },
    "WriteOwner": {
        "description": "This account can change the owner of the target object.",
        "risk": "Taking ownership lets an attacker grant themselves any permission on the target, leading to full control.",
        "mitigation": "Remove the right to change object ownership from non-administrative accounts. Ownership changes on sensitive objects should trigger alerts, as taking ownership silently grants the new owner the ability to rewrite all permissions. Legitimate ownership transfers (such as when a user leaves the organisation) should follow a documented change process.",
        "mitigation_overrides": {
            "gpo": "Remove the right to change the owner of this Group Policy from non-administrative principals. The owner can always rewrite permissions and edit the policy's contents, so unexpected ownership of a privileged policy is effectively a backdoor onto every linked system. Re-assign ownership to a dedicated administrative group through a documented change.",
            "ou": "Remove the right to change the owner of this organisational unit from non-administrative principals. Owners can rewrite the access list and inherit control over everything below the OU. Re-assign ownership to a documented administrative group.",
            "container": "Remove the right to change the owner of this container from non-administrative principals. Owners can rewrite the ACL and gain control over every child object through inheritance.",
            "enterpriseca": "Remove the right to change the owner of this Certificate Authority from non-administrative principals. The owner can rewrite the access list and gain full CA control, allowing certificates to be issued for any account. Ownership should sit with a dedicated PKI administrative group.",
            "certtemplate": "Remove the right to change the owner of this certificate template from non-administrative principals. The owner can rewrite enrolment rights on the template and configure it to issue login certificates for privileged accounts.",
            "domain": "Remove the right to change the owner of the domain object from non-administrative principals. Ownership of the domain root allows the access list to be rewritten and domain-wide privileges (such as DCSync) to be granted."
        }
    },
    "GenericWrite": {
        "description": "This account can modify key attributes on the target, such as service principal names or delegation settings.",
        "risk": "Enables Kerberoasting (offline password cracking) or delegation abuse to impersonate other users.",
        "mitigation": "Restrict write access across all properties to administrative accounts. Where a specific attribute (such as a description or phone number) needs to be updated by a service, grant the right to only that attribute rather than all. Monitor changes to sensitive attributes, particularly service principal names and delegation settings, as these are common escalation paths.",
        "mitigation_overrides": {
            "gpo": "Restrict write access on this Group Policy to administrative accounts. Modifying attributes such as the policy file path lets an attacker redirect the policy to attacker-controlled content, which is then pushed to every linked system. Limit edit rights to a small documented group and monitor changes to the policy.",
            "ou": "Restrict write access on this organisational unit to administrative accounts. Modifying OU properties (such as gpLink) lets an attacker apply malicious Group Policies across the OU. Limit to administrative accounts and monitor for unexpected attribute changes.",
            "container": "Restrict write access on this container to administrative accounts. Attribute changes on a container can affect inherited behaviour for every child object.",
            "enterpriseca": "Restrict write access on this Certificate Authority configuration to administrative accounts. Changes to CA attributes can alter trust behaviour or enable issuance of certificates for privileged accounts. Limit to dedicated PKI administrators.",
            "certtemplate": "Restrict write access on this certificate template to administrative accounts. Modifying template flags or extensions can convert it into one that issues login certificates for any account.",
            "domain": "Restrict write access on the domain object to Domain or Enterprise Admins. Modifying domain-level attributes can affect every object in the directory."
        }
    },
    "AllExtendedRights": {
        "description": "This account has all special rights on the target, including the ability to reset passwords.",
        "risk": "Allows password resets without knowing the current password, and reading sensitive attributes like LAPS passwords.",
        "mitigation": "Replace blanket extended-right grants with the specific rights that are actually needed, such as password reset, LAPS read, or mail-enable. Blanket grants usually come from older templates or convenience choices and are rarely required in practice. Review who holds AllExtendedRights on sensitive objects and reduce to targeted grants wherever possible.",
        "mitigation_overrides": {
            "domain": "AllExtendedRights at the domain root grants the directory replication rights that make up DCSync, which an attacker can use to extract every password hash in the domain. Restrict this to domain controllers and approved directory synchronisation services (such as Azure AD Connect) only, and treat any other principal with this right as a critical finding.",
            "certtemplate": "AllExtendedRights on a certificate template includes the right to enrol. Restrict enrolment to specific groups rather than granting blanket extended rights, since enrolment combined with weak template configuration can lead to login certificates being issued for privileged accounts.",
            "enterpriseca": "AllExtendedRights on the Certificate Authority covers management rights that can be used to issue or approve certificates for any account. Restrict these to a dedicated PKI administrative group and log changes to the CA configuration."
        }
    },
    "Contains": {
        "description": "The target sits inside this container or OU and inherits permissions set at the parent level.",
        "risk": "Compromising the container can affect all objects inside it through inherited permissions.",
        "mitigation": "Review permissions on parent containers and organisational units in the path, since they cascade down to every object below. Where a permission applies more broadly than needed, block inheritance on the affected child object and define explicit permissions locally. Permissions at the domain root affect every object in the domain, and default containers (such as Users and Computers) do not support blocking inheritance the way an organisational unit does, so these need particular care."
    },
    "DCSync": {
        "description": "This account can replicate password data from a domain controller, the same way DCs sync with each other.",
        "risk": "Allows extraction of every password hash in the domain, including the krbtgt hash needed for Golden Ticket attacks.",
        "mitigation": "Ensure that only domain controllers and approved directory synchronisation services (such as Azure AD Connect) hold domain replication rights. Any other account with these rights can extract every password in the domain. Monitor for replication requests from unexpected sources and treat any non-domain-controller replication activity as a credential compromise indicator."
    },
    "DumpSMSAPassword": {
        "description": "This account can retrieve the password of a standalone Managed Service Account.",
        "risk": "Provides the service account's actual password, which can be used to authenticate as that account.",
        "mitigation": "Restrict the list of principals allowed to retrieve the standalone Managed Service Account's password to only the accounts that genuinely require it. Consider migrating to Group Managed Service Accounts, which are better suited to multi-host service scenarios and have clearer access controls. Any account that does not host the service should be removed."
    },
    "GPLink": {
        "description": "This Group Policy Object is linked to the target, pushing its settings to all objects within.",
        "risk": "Controlling a linked Group Policy means controlling what software runs, what scripts execute, and what security settings apply to all targets.",
        "mitigation": "The escalation route through a linked Group Policy depends on who can edit that policy's contents, so restrict Group Policy edit rights to a small, documented administrative group. Periodically review which policies are linked to sensitive scopes (domain root, privileged organisational units) and confirm that each link is intentional. Group Policy content changes should be monitored so that unauthorised modifications are detected quickly."
    },
    "Owns": {
        "description": "This account is the owner of the target object.",
        "risk": "Owners can always change the target's permissions, even if they have no other explicit access.",
        "mitigation": "Ensure that sensitive objects (privileged users, Group Policy Objects, certificate templates) are owned by an appropriate administrative principal rather than an individual user. Owners hold implicit rights that cannot be revoked, so ownership drift is a persistent risk. Where an object is owned by an account that should not have that privilege, re-assign ownership through a documented change.",
        "mitigation_overrides": {
            "gpo": "Re-assign ownership of this Group Policy to a documented administrative group. The owner can always edit the access list and the policy's contents regardless of explicit permissions, so non-administrative ownership is effectively a persistent route to push code or settings to every linked system.",
            "ou": "Re-assign ownership of this organisational unit to a documented administrative group. Owners can rewrite the OU's access list and inherit control over every account and computer below it.",
            "container": "Re-assign ownership of this container to a documented administrative group. Owners can rewrite the access list and gain control over every child object through inheritance.",
            "enterpriseca": "Re-assign ownership of this Certificate Authority to a dedicated PKI administrative group. Owners can rewrite the CA's access list and gain full control of certificate issuance, allowing trusted login certificates to be created for any account.",
            "certtemplate": "Re-assign ownership of this certificate template to a PKI administrative group. Owners can reconfigure the template to issue login certificates for any account, which is a common route to Domain Admin.",
            "domain": "Ownership of the domain root should sit with Domain or Enterprise Admins only. Any other owner can rewrite the access list and grant themselves domain-wide privileges such as DCSync."
        }
    },
    "ReadGMSAPassword": {
        "description": "This account can read the password of a Group Managed Service Account.",
        "risk": "Provides the service account's password, allowing authentication as that service account across the domain.",
        "mitigation": "Restrict the list of principals allowed to retrieve the Group Managed Service Account's password to only the computers or accounts that host the service. An attacker who obtains this list membership can authenticate as the service account. Periodically review the list, particularly when decommissioning hosts, and remove any entries that are no longer in use."
    },
    "ReadLAPSPassword": {
        "description": "This account can read the LAPS-managed local admin password on the target computer.",
        "risk": "Provides local administrator access to the target computer, which can be used for credential theft and lateral movement.",
        "mitigation": "Restrict the right to read the LAPS-managed local administrator password to the specific helpdesk or administrative groups that need it. Ensure LAPS is configured with a short password rotation interval so that stale credentials are automatically refreshed. Where the right is broader than it needs to be, move it to a dedicated security group rather than granting it to individuals."
    },
    "SQLAdmin": {
        "description": "This account has SQL Server sysadmin privileges on the target.",
        "risk": "Can run arbitrary SQL queries, access all databases, and potentially execute OS commands via xp_cmdshell.",
        "mitigation": "Review members of the SQL Server sysadmin role and remove accounts that do not genuinely need database-wide administrative rights. Use SQL Server audit logging to track sysadmin actions, particularly operating-system command execution features. Application service accounts typically do not need sysadmin rights and can be replaced with a least-privilege role."
    },
    "SyncLAPSPassword": {
        "description": "This account can overwrite the LAPS password attribute on the target computer.",
        "risk": "An attacker can set the local admin password to a known value, creating a backdoor that persists until the next LAPS rotation.",
        "mitigation": "Remove the right to write to the LAPS password attribute from any account that does not legitimately need to reset local administrator passwords. LAPS password rotation is normally handled by the endpoint itself; any other principal writing to the attribute is unusual and should be investigated. Monitor for writes to the LAPS attribute so unauthorised overwrites can be detected."
    },
    "WriteGPLink": {
        "description": "This account can change which Group Policy Objects are linked to the target organisational unit or domain.",
        "risk": "Linking a malicious Group Policy can push code execution or security changes to every machine and user in the target scope.",
        "mitigation": "Restrict the right to link or unlink Group Policy Objects at this scope to administrative accounts. Linking a malicious Group Policy at a domain or organisational unit boundary affects every object below that point, so the blast radius is significant. Log changes to the gpLink attribute to detect unauthorised modifications."
    },
    "WriteSPN": {
        "description": "This account can set Service Principal Names on the target account.",
        "risk": "Setting a service principal name makes the target account vulnerable to offline password cracking.",
        "mitigation": "Remove the right to write service principal names from any account that does not manage services. Service accounts may legitimately have their own service principal names updated, but unrestricted rights over others' service principal names enable offline password attacks via Kerberoasting. Log changes to the servicePrincipalName attribute across the domain to detect unexpected updates."
    },
    "HasSession": {
        "description": "The target user is currently logged into this computer.",
        "risk": "An attacker with admin access to the computer can extract the logged-in user's credentials from memory.",
        "mitigation": "Avoid using privileged credentials on machines that are not tightly controlled, since cached credentials can be extracted by anyone with local administrator rights. Enable Credential Guard on supported Windows versions to protect credentials from being dumped. Use dedicated administrative workstations for privileged operations, and ensure users log off fully rather than disconnecting sessions."
    },
    "CanRDP": {
        "description": "This account can log in to the target computer via Remote Desktop.",
        "risk": "Provides interactive access to the target system where an attacker can run commands, access files, and pivot further.",
        "mitigation": "Restrict membership of the Remote Desktop Users group to only those who require interactive access to the target. Require Network Level Authentication on all Remote Desktop endpoints to reduce the risk of pre-authentication attacks. For administrative access, use dedicated jump servers rather than exposing production systems to direct Remote Desktop from general user workstations."
    },
    "CanPSRemote": {
        "description": "This account can run PowerShell commands remotely on the target computer via Windows Remote Management.",
        "risk": "Enables remote command execution on the target, which is functionally equivalent to having a shell on the machine.",
        "mitigation": "Restrict membership of the Remote Management Users group on sensitive systems, and consider requiring certificate-based authentication rather than password-based for PowerShell remoting. Just Enough Administration (JEA) constrains what remote users can do on a system, so consider deploying it on administrative endpoints so that compromised credentials have limited reach."
    },
    "ExecuteDCOM": {
        "description": "This account can execute applications remotely on the target via remote application protocols.",
        "risk": "Enables remote code execution on the target computer through remote application execution.",
        "mitigation": "Restrict membership of the Distributed COM Users group on sensitive systems to accounts that genuinely need remote application execution. Review the applications registered for remote execution on each host and remove any that are not actively used. Workstation and server images should have consistent baselines to reduce ad-hoc attack surface."
    },
    "AdminTo": {
        "description": "This account has local administrator rights on the target computer.",
        "risk": "Provides full system control, allowing credential dumping, persistence, data access, and using the machine to attack others.",
        "mitigation": "Remove local administrator rights from accounts that do not administer the specific target. Group-based membership of the local Administrators group (such as through a domain group added to every computer) is a common source of over-privilege; review whether such groups are still appropriate. Deploy LAPS so that each machine's local administrator password is unique and rotated, and use dedicated Privileged Access Workstations for administrative tasks."
    },
    "AddKeyCredential": {
        "description": "This account can add Shadow Credentials to the target, enabling certificate-based login.",
        "risk": "Allows authentication as the target without knowing or changing its password, enabling a stealthy takeover.",
        "mitigation": "Remove the right to add key credentials (also known as shadow credentials) on sensitive accounts from any principal that does not need it. Device registration and passwordless-authentication services may legitimately use this, but they should write only to their own scope. Monitor changes to the key credential link attribute, as unexpected entries on privileged accounts indicate a likely takeover attempt."
    },
    "AddKeyCredentialLink": {
        "description": "This account can add Shadow Credentials to the target, enabling certificate-based login.",
        "risk": "Allows authentication as the target without knowing or changing its password, enabling a stealthy takeover.",
        "mitigation": "Remove the right to write the key credential link attribute on sensitive accounts from any principal that does not need it. Device registration and passwordless authentication infrastructure may legitimately use this feature, but their scope should be limited to the accounts they manage. Monitor for unexpected changes on privileged accounts, as these are often a sign of takeover via shadow credentials."
    },
    "CoerceToTGT": {
        "description": "This machine can be tricked into authenticating to an attacker-controlled endpoint.",
        "risk": "The captured authentication can be relayed to other services or cracked offline to obtain credentials.",
        "mitigation": "Remove unconstrained delegation from computer and user accounts wherever possible, as it allows an attacker to collect a Ticket Granting Ticket if they can coerce authentication. Keep operating systems patched against known coercion techniques such as PetitPotam and PrinterBug. Enable Extended Protection for Authentication on services that use Kerberos or NTLM, so that captured authentication cannot be silently relayed."
    },
    "CoerceAndRelayNTLMToADCS": {
        "description": "This machine can be forced to authenticate, and that authentication relayed to the Certificate Authority to obtain a certificate in its name.",
        "risk": "If the target is a domain controller, the resulting certificate allows DCSync, which means extracting all domain password hashes.",
        "mitigation": "Enable Extended Protection for Authentication on all Certificate Authority web endpoints, and require HTTPS rather than plain HTTP for enrolment. Where NTLM is still required, limit its scope as much as possible, and monitor for NTLM authentication from unusual sources. Keep systems patched against coercion techniques (PetitPotam, PrinterBug, MS-EFSR) that drive these relay attacks."
    },
    "ForceChangePassword": {
        "description": "This account can reset the target's password without knowing the current one.",
        "risk": "Leads to immediate account takeover because the attacker sets a known password and logs in as the target.",
        "mitigation": "Remove the right to reset passwords from any account that does not require it. Helpdesk and identity management services may legitimately hold this right, but it should be scoped so that helpdesk staff cannot reset passwords on privileged accounts. Log password reset events for privileged users and alert on unexpected activity."
    },
    "ChangePassword": {
        "description": "This account can change the target's password (requires knowing the current password).",
        "risk": "If the current password is known, the attacker can change it to lock out the user and maintain their own access.",
        "mitigation": "The User-Change-Password right is held by the user themselves and, by default, Authenticated Users. If this edge appears in an escalation path, an additional principal has been explicitly granted the right on the target. Review whether that grant is intentional and remove it if not. Strong password policies and lockout thresholds also reduce the risk that a known password is maliciously changed and the account taken over."
    },
    "AllowedToAct": {
        "description": "The target trusts this account to impersonate users through Resource-Based Constrained Delegation.",
        "risk": "An attacker controlling this account can authenticate to the target service as any user, including administrators.",
        "mitigation": "Audit the list of principals in the target's resource-based constrained delegation configuration and remove any that are no longer required. Delegation is a legitimate feature where a service needs to forward user credentials to another service, but it should be reviewed periodically. Monitor writes to the delegation attribute so unauthorised grants are detected."
    },
    "AllowedToDelegate": {
        "description": "This account is trusted to delegate user credentials to specific services on the target.",
        "risk": "An attacker can impersonate users when accessing the delegated service, potentially gaining admin-level access.",
        "mitigation": "Review the services this account is configured to delegate to, and remove any that are no longer required. Constrained delegation is valid where a service needs to access back-end resources on behalf of users, but unused entries are often forgotten and can become attack paths. Resource-based constrained delegation is easier to audit and should be preferred where possible."
    },
    "ADCSESC1": {
        "description": "A certificate template allows the requester to specify who the certificate is for (Subject Alternative Name).",
        "risk": "An attacker can request a certificate as Domain Admin because the template allows specifying an arbitrary identity.",
        "mitigation": "Remove the setting that lets enrollees supply their own subject name from any certificate template that issues authentication certificates. Restrict enrolment on authentication templates to specific user groups rather than low-privilege defaults. Where templates must allow enrollee-supplied subjects for business reasons, require manager approval on the Certificate Authority before issuance."
    },
    "ADCSESC2": {
        "description": "A certificate template is configured with 'Any Purpose' or SubCA usage, so the certificate works for everything.",
        "risk": "The resulting certificate can be used for authentication, code signing, or any other purpose.",
        "mitigation": "Configure certificate templates with the specific extended key usages they need (client authentication, code signing, etc.) rather than the Any Purpose option, which bypasses intended restrictions. SubCA templates are particularly sensitive and should only be enrollable by a small set of Public Key Infrastructure administrators. Review enrolment permissions on all templates and remove low-privilege groups where inappropriate."
    },
    "ADCSESC3": {
        "description": "A certificate template allows this account to request certificates on behalf of other users.",
        "risk": "An attacker can obtain certificates for any user in the domain, including Domain Admins.",
        "mitigation": "Restrict the Certificate Request Agent enrolment permission to dedicated enrolment stations and designated staff, not general users. Configure the Certificate Authority to restrict which agents can request certificates on behalf of which target users and for which templates. Unrestricted enrolment agents can request certificates for any identity, including privileged accounts."
    },
    "ADCSESC4": {
        "description": "This account can modify a certificate template's configuration.",
        "risk": "The template can be reconfigured to allow arbitrary certificate requests (like ESC1), then exploited.",
        "mitigation": "Remove write access on certificate templates from any account that is not a designated Public Key Infrastructure administrator. Template modification allows a template to be reconfigured to issue certificates for arbitrary identities, so this permission is sensitive. Monitor changes to template configurations and access lists so unauthorised modifications are detected early."
    },
    "ADCSESC5": {
        "description": "This account has write access to Public Key Infrastructure objects in the Configuration container, such as the NTAuthCertificates store or the Certificate Authority object.",
        "risk": "An attacker can inject a rogue Certificate Authority into the trust store, which lets it issue certificates that domain controllers will accept for authentication as any user.",
        "mitigation": "Audit access controls on the NTAuthCertificates, AIA, and Certificate Authority configuration objects in the Configuration container, and restrict write access to dedicated Public Key Infrastructure administrators. Adding an entry to NTAuthCertificates makes a Certificate Authority trusted for domain authentication, so any write there is a high-impact change. Monitor modifications to these objects and treat unexpected changes as a likely compromise indicator."
    },
    "ADCSESC6a": {
        "description": "The Certificate Authority allows any requester to specify an alternative identity, regardless of template settings.",
        "risk": "Any user who can enroll can request a certificate as any other user, including Domain Admin.",
        "mitigation": "Ensure the Certificate Authority is not configured to accept arbitrary subject alternative names on certificate requests, which bypasses template-level restrictions. This setting is rarely required in modern environments and is a common source of privilege escalation. If it is currently enabled, verify whether the applications that depend on it can be migrated to a safer configuration before disabling."
    },
    "ADCSESC6b": {
        "description": "The Certificate Authority's identity override setting combined with weak certificate mapping bypasses security patches.",
        "risk": "Patched protections are circumvented, so attackers can still request certificates as arbitrary identities.",
        "mitigation": "Apply all available Active Directory Certificate Services patches to the Certificate Authority and domain controllers. Configure strong certificate binding enforcement so that weak certificate-to-account mappings are rejected. Review the Certificate Authority's subject alternative name handling configuration and tighten it if it still allows arbitrary values."
    },
    "ADCSESC7": {
        "description": "This account can manage the Certificate Authority or approve certificate requests.",
        "risk": "An attacker can approve their own denied certificate requests or issue certificates for privileged accounts.",
        "mitigation": "Restrict Manage CA and Manage Certificates rights to a small group of designated Public Key Infrastructure administrators. These rights allow bypassing the normal certificate request approval flow, so they should not be granted to general IT staff. Periodically review who holds these rights and confirm that each holder's role still requires them."
    },
    "ADCSESC8": {
        "description": "The Certificate Authority's web enrollment endpoint accepts authentication without relay protection.",
        "risk": "An attacker can relay captured authentication to the Certificate Authority and obtain a certificate as the relayed identity.",
        "mitigation": "Enable Extended Protection for Authentication on the Certificate Authority's web enrolment endpoints to prevent relayed authentication. Enforce HTTPS for all enrolment traffic and disable the plain HTTP endpoint where it is not required. If web enrolment is not used at all, consider disabling the role entirely to reduce attack surface."
    },
    "ADCSESC9a": {
        "description": "A certificate template is missing security extensions that tie the certificate to a specific account.",
        "risk": "Certificates issued from this template can potentially be used for authentication in unintended contexts.",
        "mitigation": "Ensure certificate templates that issue authentication certificates include the security extension that binds the certificate to a specific account. Configure strong certificate binding enforcement on domain controllers so that certificates missing this extension are not accepted for authentication. Templates that do not meet this requirement should be updated or retired."
    },
    "ADCSESC9b": {
        "description": "A certificate template lacks proper security extension validation.",
        "risk": "Weak validation allows certificates to be accepted for authentication when they should be rejected.",
        "mitigation": "Apply all Active Directory Certificate Services security updates on domain controllers and Certificate Authorities. Configure strict certificate-to-account mapping, so that only strongly-bound certificates are accepted for authentication. Weak mapping configurations are a common source of authentication bypass, and they should be replaced with explicit mappings wherever possible."
    },
    "ADCSESC10a": {
        "description": "The domain uses weak certificate-to-account mapping, preferring the Subject Alternative Name over the User Principal Name.",
        "risk": "An attacker can manipulate certificate attributes to authenticate as a different, more privileged user.",
        "mitigation": "Configure domain controllers to use strong, explicit certificate-to-account mapping rather than relying on the subject alternative name alone. Weak mapping allows an attacker to manipulate certificate fields to authenticate as a different identity. Apply the related security patches and monitor authentication logs for certificate-based logon anomalies."
    },
    "ADCSESC10b": {
        "description": "The Certificate Authority's identity override setting combined with weak certificate mapping bypasses multiple security layers.",
        "risk": "Chaining these misconfigurations allows authentication as any user via crafted certificate requests.",
        "mitigation": "This escalation chains two misconfigurations: an overly permissive Certificate Authority setting and weak certificate-to-account mapping on domain controllers. Address both by tightening the Certificate Authority's subject alternative name handling and enabling strong binding enforcement on domain controllers. All related Active Directory Certificate Services patches should also be applied."
    },
    "ADCSESC11": {
        "description": "The Certificate Authority's remote interface does not require encrypted requests, making it vulnerable to authentication relay.",
        "risk": "An attacker can relay authentication to the Certificate Authority's remote interface and obtain unauthorized certificates.",
        "mitigation": "Configure the Certificate Authority's remote interface to require encrypted and signed requests, so that unencrypted relay attempts are rejected. Review the network exposure of the Certificate Authority's remote procedure call endpoints and restrict them to administrative networks where possible."
    },
    "ADCSESC12": {
        "description": "Certificate infrastructure objects in Active Directory have overly permissive access controls.",
        "risk": "An attacker can modify the certificate infrastructure to compromise trust and issuance controls.",
        "mitigation": "Audit access controls on Public Key Infrastructure objects in Active Directory, including Certificate Authority configuration objects and enrolment service entries. These objects are often overlooked during access reviews, so stale or overly broad permissions accumulate over time. Restrict write access to dedicated Public Key Infrastructure administrators."
    },
    "ADCSESC13": {
        "description": "The certificate approval process can be bypassed due to misconfigured issuance policies.",
        "risk": "An attacker can obtain certificates that should require manager approval, escalating privileges.",
        "mitigation": "Configure sensitive certificate templates to require Certificate Authority manager approval before a certificate is issued. Review issuance policy assignments to ensure that templates do not unintentionally grant privileged access through policy-based evaluation. Templates tied to authentication for privileged accounts should have the most stringent controls."
    },
    "GoldenCert": {
        "description": "This account has access to the Certificate Authority's private key, which is the master key for all certificates.",
        "risk": "Can forge certificates for any identity in the domain. This is persistent access that survives password resets and account changes.",
        "mitigation": "Protect the Certificate Authority's private key with a hardware security module so that it cannot be extracted from the server. Restrict administrative access to Certificate Authority systems and treat them as tier-zero infrastructure. Monitor certificate issuance patterns and investigate any that do not match known enrolment activity."
    },
    "ManageCA": {
        "description": "This account is an administrator of the Certificate Authority.",
        "risk": "Full control over the Certificate Authority, allowing issuance of certificates for any identity and changes to its configuration.",
        "mitigation": "Restrict Certificate Authority administrator rights to a small group of designated Public Key Infrastructure administrators. Role separation on the Certificate Authority, where certificate approval and Certificate Authority management are held by different principals, reduces the impact of a single account compromise. General IT administrators should not hold these rights."
    },
    "ManageCertificates": {
        "description": "This account can approve, deny, or revoke certificates on the Certificate Authority.",
        "risk": "Can approve pending certificate requests for privileged identities that would otherwise be denied.",
        "mitigation": "Restrict the right to approve, deny, or revoke certificates to a small group of designated Public Key Infrastructure staff. Monitor certificate approval events, particularly for templates that issue authentication certificates. Automated approval processes should be reviewed to ensure they cannot be abused to bypass manager approval requirements."
    },
    "WriteAccountRestrictions": {
        "description": "This account can modify security-related account settings on the target, like account control flags.",
        "risk": "Can disable security controls on the target account, enable delegation, or change restrictions to enable further attacks.",
        "mitigation": "Remove the right to modify account security settings (User Account Control flags, account expiry, delegation settings) from any account that does not administer user lifecycle. Changes to these settings can disable security controls or enable delegation, so they should be logged and alerted on. Monitor for writes to the userAccountControl attribute on sensitive accounts."
    },
    "MemberOfLocalGroup": {
        "description": "This account is a member of a local security group on the target computer.",
        "risk": "Local group membership can grant administrative access, remote login, or remote execution rights on the target machine.",
        "mitigation": "Audit local group memberships on sensitive systems, particularly local Administrators, Remote Desktop Users, and Distributed COM Users. Remove accounts that no longer require local access, especially where they have been added individually rather than through a managed group. Consider managing local group membership centrally via Group Policy Preferences so that drift is prevented."
    },
    "RemoteInteractiveLogonRight": {
        "description": "This account has been granted the right to log on interactively via Remote Desktop on the target computer.",
        "risk": "Provides interactive remote access to the target, where an attacker can run commands, access files, and escalate privileges.",
        "mitigation": "Restrict the right to log on remotely via Remote Desktop to specifically authorised users, managed through Group Policy on each target system. Default user rights assignments often include broad Remote Desktop access that is not operationally required. Review the assigned principals on sensitive systems and remove any that do not genuinely need interactive remote access."
    },
    "AddAllowedToAct": {
        "description": "This account can write the attribute that controls which principals are allowed to act on behalf of the target computer (Resource-Based Constrained Delegation).",
        "risk": "Lets an attacker register their own controlled account as a delegate, then use Kerberos to authenticate as any user (including administrators) when accessing the target.",
        "mitigation": "Restrict the right to write msDS-AllowedToActOnBehalfOfOtherIdentity on computer accounts to administrators only. Resource-based constrained delegation is rarely needed in normal operations; legitimate uses (such as service deployments) should be performed through change-controlled accounts and audited. Monitor changes to the attribute, as unexpected entries on a computer object are a strong indicator of an in-progress impersonation attack."
    },
    "CoerceAndRelayNTLMToSMB": {
        "description": "This account can coerce authentication from the target computer and relay it to a file sharing service to authenticate as the target.",
        "risk": "Successful relay grants the attacker access to file shares or local administrator rights on the relayed service, leading to credential theft and lateral movement.",
        "mitigation": "Enable SMB signing on all Windows hosts, particularly file servers and domain controllers, so that relayed sessions are rejected by the receiving service. Patch operating systems against known coercion techniques such as PetitPotam, PrinterBug, and DFSCoerce. On hosts that do not require them, disable the Print Spooler and WebClient services to reduce the surface for coerced authentication."
    },
    "CoerceAndRelayNTLMToLDAP": {
        "description": "This account can coerce authentication from the target computer and relay it to the directory service on a domain controller to gain write access as the target.",
        "risk": "Successful relay lets the attacker modify directory objects (such as adding shadow credentials or resource-based delegation entries) as the coerced computer account, which is a common route to full takeover of that account.",
        "mitigation": "Enable LDAP signing on all domain controllers so that unsigned relayed sessions are rejected. Patch operating systems against known coercion techniques (PetitPotam, PrinterBug). Where possible, disable NTLM authentication on domain controllers entirely and require Kerberos, which is not vulnerable to relay attacks of this kind."
    },
    "CoerceAndRelayNTLMToLDAPS": {
        "description": "This account can coerce authentication from the target computer and relay it to an encrypted directory service on a domain controller, gaining write access as the target.",
        "risk": "Successful relay lets the attacker modify directory objects as the coerced computer account, which is a common route to take over the account or configure delegation routes from it.",
        "mitigation": "Enforce LDAP channel binding (Extended Protection for Authentication) on all domain controllers so that NTLM sessions cannot be relayed across a TLS channel. Patch operating systems against known coercion techniques and reduce reliance on NTLM where Kerberos is supported. Investigate any LDAPS authentication from a computer account where the source matches a known coercion technique."
    },
    "HasSIDHistory": {
        "description": "This account has the security identifier of another principal in its sidHistory attribute, so it carries the original principal's access in addition to its own.",
        "risk": "If the original principal was privileged, the current account inherits that privilege transitively. Adding entries to sidHistory is also a known persistence technique used by attackers after a domain compromise.",
        "mitigation": "Audit the sidHistory attribute across all accounts and groups, particularly after domain consolidation or migration projects. Where the migration is complete, remove sidHistory entries, as they are a common persistence mechanism abused by attackers and rarely required after a migration finishes. Any sidHistory entry pointing into a privileged group SID (such as Domain Admins from any domain) should be treated as a critical finding and investigated."
    },
    "AbuseTGTDelegation": {
        "description": "This account is configured for unconstrained delegation, so when a privileged user authenticates to it, their full Kerberos Ticket Granting Ticket is stored on the host and can be reused.",
        "risk": "An attacker who controls a host with unconstrained delegation can coerce a Domain Controller or another privileged account to authenticate to it, capture the resulting Ticket Granting Ticket, and use it to impersonate that account anywhere in the domain.",
        "mitigation": "Remove unconstrained delegation from any account that does not strictly require it; constrained delegation or resource-based constrained delegation are safer alternatives in almost all cases. Add sensitive accounts (Domain Admins, service accounts that handle critical data) to the Protected Users group and mark them as 'Account is sensitive and cannot be delegated' so that their tickets cannot be captured this way. Monitor for ticket-collection patterns (large numbers of TGTs cached on a single host) as an indicator of in-progress abuse."
    },
    "HasTrustKeys": {
        "description": "This account has access to the cryptographic keys that authenticate the target trust between two domains or forests.",
        "risk": "Trust keys can be used to forge inter-realm Kerberos tickets, allowing an attacker to authenticate as any user across the trust boundary, which is a forest-wide compromise route.",
        "mitigation": "Restrict access to trust account credentials to Domain Controllers and dedicated administrative roles only. Rotate trust keys after any suspected compromise of either side of the trust. Monitor authentication patterns across trust boundaries for anomalies that could indicate forged tickets, and treat unexpected access to trust account secrets as a critical incident."
    },
    "CrossForestTrust": {
        "description": "A trust relationship between this domain and a domain in another Active Directory forest, allowing principals from one forest to authenticate to resources in the other.",
        "risk": "If either forest is compromised, the trust can be used to extend the compromise to the other forest. Forest trusts also expand the attack surface that defenders need to monitor.",
        "mitigation": "Review the necessity of every cross-forest trust regularly and remove any that are no longer required. Where trusts are needed, enable SID filtering and selective authentication so that compromised principals on one side cannot freely act on the other. Treat the trusted forest's security posture as part of your own; a weakness there becomes a weakness here."
    },
    "LocalAdminRequired": {
        "description": "This account holds local administrator rights on the target computer, identified through System Center Configuration Manager (SCCM) data.",
        "risk": "Provides full system control on the target, allowing credential dumping, persistence, and lateral movement. SCCM-managed administrative rights often grant access to a large estate of machines through a single role.",
        "mitigation": "Treat SCCM-derived local administrator assignments the same way as standard local administrator membership: review who has it, remove accounts that no longer need it, and prefer dedicated administrative groups over individual user grants. SCCM itself should be considered a tier-zero asset because compromise of the site server typically allows code to be pushed to every managed client."
    },
    "CoerceAndRelayToSMB": {
        "description": "This account can coerce authentication from the target computer and relay it to a file sharing service to authenticate as the target. Identified through System Center Configuration Manager (SCCM) relay analysis.",
        "risk": "Successful relay grants the attacker access to file shares or local administrator rights on the relayed service, which is a route to credential theft and lateral movement, particularly across SCCM-managed infrastructure.",
        "mitigation": "Enable SMB signing on all Windows hosts, particularly file servers, SCCM site servers, and domain controllers, so that relayed sessions are rejected by the receiving service. Patch operating systems against known coercion techniques (PetitPotam, PrinterBug, DFSCoerce). Disable the Print Spooler and WebClient services on hosts that do not need them to reduce coercion surface."
    },
    "CoerceAndRelayToMSSQL": {
        "description": "This account can coerce authentication from the target and relay it to a Microsoft SQL Server, authenticating as the coerced account. Identified through System Center Configuration Manager (SCCM) relay analysis.",
        "risk": "Successful relay grants the attacker the coerced account's SQL Server access, which on SCCM databases typically means full administrative control of the SCCM site and every managed client.",
        "mitigation": "Require SQL Server connections to use Extended Protection for Authentication and disable NTLM where Kerberos is supported. Restrict who can authenticate to the SCCM database; service accounts and site-server hosts should be the only principals with sysadmin rights. Patch coercion vulnerabilities (PetitPotam, PrinterBug) and enable SMB signing across the estate."
    },
    "CoerceAndRelayToAdminService": {
        "description": "This account can coerce authentication from the target and relay it to the System Center Configuration Manager (SCCM) management interface, authenticating as the coerced account.",
        "risk": "Successful relay against the AdminService grants the attacker the coerced account's SCCM rights, which in many environments includes full SCCM administrator, allowing arbitrary code execution on every managed client.",
        "mitigation": "Configure the SCCM AdminService to require Extended Protection for Authentication (EPA) and enforce HTTPS so that NTLM relay attacks cannot succeed. Restrict the SCCM administrator role to a small documented group, and treat the SCCM site server as tier-zero infrastructure because compromise of it equates to compromise of every managed client. Patch coercion vulnerabilities on all Windows hosts."
    },
    "CoerceAndRelayToADCS": {
        "description": "This account can coerce authentication from the target and relay it to the Certificate Authority's web enrolment endpoint, obtaining a certificate that authenticates as the coerced account.",
        "risk": "Successful relay yields a login certificate for the coerced account. Where the coerced account is a domain controller or other privileged principal, this leads directly to full domain compromise.",
        "mitigation": "Enable Extended Protection for Authentication (EPA) on the Certificate Authority's web enrolment endpoint, or disable HTTP enrolment entirely and use HTTPS only with channel binding. Patch operating systems against known coercion techniques (PetitPotam, PrinterBug). Where possible, disable NTLM on the Certificate Authority and require Kerberos."
    },
}

_warned = set()


def get_edge_info(edge_type):
    entry = EDGE_GLOSSARY.get(edge_type)
    if entry is None and edge_type not in _warned:
        _warned.add(edge_type)
        print(f"Warning: Edge type '{edge_type}' missing from EDGE_GLOSSARY — no tooltip or mitigation will be shown.")
    return entry
