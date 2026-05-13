
import json
import os
import re
import html
import hashlib
from datetime import datetime

from .edge_glossary import get_edge_info
from .shared_powershell import Utils, PowerShellCommandGenerator
from .hv_groups import HIGH_VALUE_GROUPS_UPPER

# Edges suppressed from the client HTML report (still shown in .txt for consultants)
_SUPPRESSED_EDGES = {
    'HasSession',           # Informational — not an exploitable escalation step
    'TrustedBy',            # Domain trust direction — structural, not actionable
    'NTAuthStoreFor',       # Certificate plumbing — ADCSESC edges cover the attack
    'IssuedSignedBy',       # Certificate plumbing
    'EnrollOnBehalfOf',     # Certificate plumbing — covered by ESC3
}

_ENTITY_SOURCE_TOOLTIP_LIMIT = 20
_DEFAULT_DESCRIPTION = 'No description available'


def _parse_path_string(path_string):
    # format: Edge -> Node (Type) -> Edge -> Node (Type) -> ...
    parts = [p.strip() for p in path_string.split('->')]
    steps = []
    for i in range(0, len(parts) - 1, 2):
        edge = parts[i]
        node_part = parts[i + 1] if i + 1 < len(parts) else ''
        m = re.match(r'^(.*?)\s*\((\w[\w\s]*)\)\s*$', node_part)
        if m:
            node_name = m.group(1).strip()
            node_type = m.group(2).strip()
        else:
            node_name = node_part.strip()
            node_type = ''
        steps.append({'node': node_name, 'node_type': node_type, 'edge': edge})
    return steps


def _generate_powershell_for_path(path_details, domain_name, domain_controller, domain_sid):
    spn = path_details.get('shortest_path_names', [])
    pod = path_details.get('path_object_details', {})
    if not spn or len(spn) < 3:
        return []

    cmd_gen = PowerShellCommandGenerator(domain_controller, domain_name, domain_sid)
    steps = []

    first_node = spn[0]
    entity_sid = ''
    if isinstance(first_node, dict):
        entity_sid = first_node.get('objectid', '') or ''
        if '-S-1-' in entity_sid and not entity_sid.startswith('S-1-'):
            idx = entity_sid.find('S-1-')
            if idx >= 0:
                entity_sid = entity_sid[idx:]

    for i in range(0, len(spn) - 1, 2):
        source_element = spn[i] if i < len(spn) else None
        relationship_element = spn[i + 1] if (i + 1) < len(spn) else None
        target_element = spn[i + 2] if (i + 2) < len(spn) else None

        source_name = Utils.get_element_string(source_element) or ''
        relationship = Utils.get_element_string(relationship_element) or ''
        target_name = Utils.get_element_string(target_element) or ''

        source_detail = pod.get(source_name, {})
        if not source_detail and isinstance(source_element, dict):
            source_detail = source_element
        target_detail = pod.get(target_name, {})
        if not target_detail and isinstance(target_element, dict):
            target_detail = target_element

        current_sid = entity_sid
        if source_detail and isinstance(source_detail, dict):
            if 'sid' in source_detail and source_detail['sid']:
                current_sid = source_detail['sid']
            elif 'objectid' in source_detail:
                raw = source_detail['objectid']
                if isinstance(raw, str) and 'S-1-' in raw and not raw.startswith('S-1-'):
                    idx = raw.find('S-1-')
                    if idx >= 0:
                        current_sid = raw[idx:]
                elif isinstance(raw, str):
                    current_sid = raw

        cmd = cmd_gen.generate_relationship_command(
            relationship, source_name, target_name,
            source_detail, target_detail, current_sid
        )
        steps.append({
            'source': source_name,
            'edge': relationship,
            'target': target_name,
            'command': (cmd or '').strip()
        })

    return steps



def _build_path_svg(steps, source_label='Affected Entities', source_count=0, dest_tip='', source_tip=''):
    if not steps:
        return ''

    node_h = 48
    node_pad_x = 20
    char_w = 8.0              # Arial 11px uppercase; generous to prevent overflow
    min_gap = 24              # minimum gap (just arrow room)
    edge_char_w = 6.2         # Arial 9.5px edge labels
    edge_label_pad = 26       # breathing room around edge label text
    pad_y = 28
    pad_x = 14

    src_text = f'{source_label} ({source_count})' if source_count else source_label
    nodes = [{'label': src_text, 'type': '', 'cls': 'pg-node-src'}]
    for i, s in enumerate(steps):
        cls = 'pg-node-dst' if i == len(steps) - 1 else 'pg-node'
        nodes.append({'label': s['node'], 'type': s['node_type'], 'cls': cls})

    edges = [s['edge'] for s in steps]

    for n in nodes:
        display_len = min(len(n['label']), 28)
        type_len = len(n['type']) if n['type'] else 0
        text_w = max(display_len, type_len) * char_w
        n['w'] = max(text_w + node_pad_x * 2, 110)

    # per-edge gap so long labels don't overlap
    gaps = []
    for i in range(len(nodes) - 1):
        elabel = edges[i] if i < len(edges) else ''
        label_w = len(elabel) * edge_char_w + edge_label_pad if elabel else 0
        gaps.append(max(min_gap, label_w))

    total_w = int(pad_x * 2 + sum(n['w'] for n in nodes) + sum(gaps) + 1)
    svg_h = node_h + pad_y * 2 + 4

    parts = [f'<div class="path-graph"><svg width="{total_w}" height="{svg_h}" xmlns="http://www.w3.org/2000/svg">']
    parts.append('<defs><marker id="ah" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">'
                 '<path d="M0,0 L8,3 L0,6 Z" class="pg-arrow"/></marker></defs>')

    cy = pad_y + node_h // 2
    x = pad_x

    for i, n in enumerate(nodes):
        nw = n['w']
        is_last = (i == len(nodes) - 1)

        # Wrap source/dest nodes in <g> with tooltip if available
        has_tip = False
        if i == 0 and source_tip:
            parts.append(f'<g class="ent-hover" data-tip="{source_tip}" style="cursor:pointer">')
            has_tip = True
        elif is_last and dest_tip:
            parts.append(f'<g class="ent-hover" data-tip="{dest_tip}" style="cursor:pointer">')
            has_tip = True

        parts.append(f'<rect x="{x}" y="{pad_y}" width="{nw}" height="{node_h}" class="{n["cls"]}" rx="6" ry="6"/>')

        label_cx = x + nw / 2
        display_label = n['label'] if len(n['label']) <= 28 else n['label'][:26] + '..'

        if n['type']:
            parts.append(f'<text x="{label_cx}" y="{cy - 6}" class="pg-label">{_h(display_label)}</text>')
            parts.append(f'<text x="{label_cx}" y="{cy + 9}" class="pg-type">{_h(n["type"])}</text>')
        else:
            parts.append(f'<text x="{label_cx}" y="{cy}" class="pg-label">{_h(display_label)}</text>')

        if has_tip:
            parts.append('</g>')

        if i < len(nodes) - 1:
            g = gaps[i]
            x1 = x + nw
            x2 = x1 + g
            edge_label = edges[i] if i < len(edges) else ''

            parts.append(f'<line x1="{x1}" y1="{cy}" x2="{x2 - 2}" y2="{cy}" class="pg-edge" marker-end="url(#ah)"/>')
            if edge_label:
                lx = x1 + g / 2
                ei = get_edge_info(edge_label)
                if ei:
                    etip = f"{_h(edge_label)}&lt;br&gt;{_h(ei['description'])}&lt;br&gt;&lt;br&gt;Risk: {_h(ei['risk'])}".replace('"', '&quot;')
                    lw = len(edge_label) * edge_char_w + 12
                    parts.append(f'<g class="ent-hover edge-tip" data-tip="{etip}" style="cursor:help">')
                    parts.append(f'<rect x="{lx - lw/2}" y="{cy - 20}" width="{lw}" height="16" fill="transparent"/>')
                    parts.append(f'<text x="{lx}" y="{cy - 8}" class="pg-edge-label" style="pointer-events:none">{_h(edge_label)}</text>')
                    parts.append('</g>')
                else:
                    parts.append(f'<text x="{lx}" y="{cy - 8}" class="pg-edge-label">{_h(edge_label)}</text>')

            x = x2

    parts.append('</svg></div>')
    return '\n'.join(parts)


def _build_step_svg(source, edge, target):
    node_h = 36
    pad_x = 10
    pad_y = 20
    char_w = 7.6
    node_pad = 16
    edge_cw = 6.0

    src_label = source.split('@')[0] if '@' in source else source
    tgt_label = target.split('@')[0] if '@' in target else target
    src_label = src_label if len(src_label) <= 24 else src_label[:22] + '..'
    tgt_label = tgt_label if len(tgt_label) <= 24 else tgt_label[:22] + '..'

    src_w = max(len(src_label) * char_w + node_pad * 2, 90)
    tgt_w = max(len(tgt_label) * char_w + node_pad * 2, 90)
    edge_w = max(len(edge) * edge_cw + 24, 40)
    total_w = int(pad_x * 2 + src_w + edge_w + tgt_w + 1)
    svg_h = node_h + pad_y * 2

    cy = pad_y + node_h // 2
    p = []
    p.append(f'<div class="path-graph" style="margin:4px 0"><svg width="{total_w}" height="{svg_h}" xmlns="http://www.w3.org/2000/svg">')
    p.append('<defs><marker id="ahm" markerWidth="7" markerHeight="5" refX="7" refY="2.5" orient="auto">'
             '<path d="M0,0 L7,2.5 L0,5 Z" class="pg-arrow"/></marker></defs>')

    x = pad_x
    p.append(f'<rect x="{x}" y="{pad_y}" width="{src_w}" height="{node_h}" class="pg-node" rx="5" ry="5"/>')
    p.append(f'<text x="{x + src_w/2}" y="{cy}" class="pg-label">{_h(src_label)}</text>')

    x1 = x + src_w
    x2 = x1 + edge_w
    p.append(f'<line x1="{x1}" y1="{cy}" x2="{x2 - 2}" y2="{cy}" class="pg-edge" marker-end="url(#ahm)"/>')
    ei = get_edge_info(edge)
    emx = x1 + edge_w / 2
    if ei:
        etip = f"{_h(edge)}&lt;br&gt;{_h(ei['description'])}&lt;br&gt;&lt;br&gt;Risk: {_h(ei['risk'])}".replace('"', '&quot;')
        elw = len(edge) * edge_cw + 12
        p.append(f'<g class="ent-hover edge-tip" data-tip="{etip}" style="cursor:help">')
        p.append(f'<rect x="{emx - elw/2}" y="{cy - 19}" width="{elw}" height="16" fill="transparent"/>')
        p.append(f'<text x="{emx}" y="{cy - 7}" class="pg-edge-label" style="pointer-events:none">{_h(edge)}</text>')
        p.append('</g>')
    else:
        p.append(f'<text x="{emx}" y="{cy - 7}" class="pg-edge-label">{_h(edge)}</text>')

    p.append(f'<rect x="{x2}" y="{pad_y}" width="{tgt_w}" height="{node_h}" class="pg-node-dst" rx="5" ry="5"/>')
    p.append(f'<text x="{x2 + tgt_w/2}" y="{cy}" class="pg-label">{_h(tgt_label)}</text>')

    p.append('</svg></div>')
    return '\n'.join(p)


def _ps_step_explanation(edge, source, target):
    src = source.split('@')[0] if '@' in source else source
    tgt = target.split('@')[0] if '@' in target else target

    explanations = {
        'MemberOf': (f'Checks whether {src} is a member of the {tgt} group. '
                     f'If the output shows a row with Status equal to Member, the membership is confirmed.'),
        'GenericAll': (f'Queries the access control list on {tgt} for permissions held by {src}. '
                       f'If a row is returned with ActiveDirectoryRights containing GenericAll, the access is confirmed.'),
        'GenericWrite': (f'Queries the permissions on {tgt} for write access held by {src}. '
                         f'If a row is returned with ActiveDirectoryRights containing GenericWrite or WriteProperty, the access is confirmed.'),
        'WriteDacl': (f'Checks whether {src} can modify the security descriptor of {tgt}. '
                      f'If a row is returned with ActiveDirectoryRights containing WriteDacl, the access is confirmed.'),
        'WriteOwner': (f'Checks whether {src} can change the owner of {tgt}. '
                       f'If a row is returned with ActiveDirectoryRights containing WriteOwner, the permission exists.'),
        'Owns': (f'Checks whether {src} is listed as the owner of {tgt}. '
                 f'If the output returns an Owner entry matching {src} (directly or via group), ownership is confirmed.'),
        'DCSync': (f'Checks whether {src} has replication rights (DS-Replication-Get-Changes) on the domain. '
                   f'If the output returns a row with ActiveDirectoryRights equal to DS-Replication-Get-Changes or DS-Replication-Get-Changes-All, DCSync is possible.'),
        'AdminTo': (f'This requires local access to {tgt} to verify admin group membership. '
                    f'If {src} or a group {src} belongs to appears in the local Administrators group, administrative access is confirmed.'),
        'CanRDP': (f'Checks whether {src} is in the Remote Desktop Users group on {tgt}. '
                   f'If the listed group members include {src} or a group {src} belongs to, Remote Desktop access is confirmed.'),
        'CanPSRemote': (f'Checks whether {src} is in the Remote Management Users group on {tgt}. '
                        f'If the listed group members include {src} or a group {src} belongs to, PowerShell remoting access is confirmed.'),
        'ForceChangePassword': (f'Checks whether {src} has the ExtendedRight to reset the password of {tgt}. '
                                f'If the output returns a row with ActiveDirectoryRights containing ExtendedRight (User-Force-Change-Password), the password reset right is confirmed.'),
        'ReadLAPSPassword': (f'Checks whether {src} can read the LAPS password attribute on {tgt}. '
                             f'If the output returns a row with ObjectType ms-Mcs-AdmPwd and ActiveDirectoryRights ReadProperty, LAPS read access is confirmed.'),
        'ReadGMSAPassword': (f'Checks whether {src} is listed in the PrincipalsAllowedToRetrieveManagedPassword for {tgt}. '
                             f'If the output returns a row naming {src} (or a group {src} belongs to) as the Principal, the service account password can be retrieved.'),
        'AllowedToAct': (f'Checks whether {src} is listed in the resource-based constrained delegation configuration on {tgt}. '
                         f'If the output returns a row with ActiveDirectoryRights equal to AllowedToAct and IdentityReference matching {src}, delegation is confirmed.'),
        'AllowedToDelegate': (f'Checks whether {src} has constrained delegation rights to {tgt}. '
                              f'If the msDS-AllowedToDelegateTo output lists a service on {tgt}, delegation is configured.'),
        'AddKeyCredential': (f'Checks whether {src} can write to the msDS-KeyCredentialLink attribute on {tgt}. '
                             f'If the output returns a row with ObjectType msDS-KeyCredentialLink and ActiveDirectoryRights WriteProperty, Shadow Credentials can be added.'),
        'AddKeyCredentialLink': (f'Checks whether {src} can write to the msDS-KeyCredentialLink attribute on {tgt}. '
                                 f'If the output returns a row with ObjectType msDS-KeyCredentialLink and ActiveDirectoryRights WriteProperty, Shadow Credentials can be added.'),
        'CoerceAndRelayNTLMToADCS': (f'Checks the permissions on {tgt} held by {src}, which validates that authentication can be relayed to the Certificate Authority. '
                                     f'The coercion step itself (PetitPotam, PrinterBug, etc.) requires network-level testing separately. '
                                     f'If the permission query returns a row naming {src} with rights on {tgt}, the relay prerequisites are in place.'),
        'CoerceToTGT': (f'Checks delegation settings on {src} that could allow authentication coercion. '
                        f'If the output shows TrustedForDelegation set to True or TrustedToAuthForDelegation set to True, coercion-to-TGT is possible.'),
        'GoldenCert': (f'This relationship indicates access to the CA private key, so verification requires checking who can reach the CA server and its key storage. '
                       f'If unexpected accounts hold administrative access to the CA host or its HSM/key store, the risk is confirmed.'),
        'AllExtendedRights': (f'Checks whether {src} has AllExtendedRights on {tgt}, which includes password reset and reading sensitive attributes. '
                              f'If AllExtendedRights appears in the output, the right is confirmed.'),
        'WriteGPLink': (f'Checks whether {src} can modify the gpLink attribute on {tgt}. '
                        f'If the output returns a row with ObjectType gpLink and ActiveDirectoryRights WriteProperty, linking or unlinking Group Policy on this scope is possible.'),
        'WriteSPN': (f'Checks whether {src} can modify the servicePrincipalName attribute on {tgt}. '
                     f'If the output returns a row with ObjectType servicePrincipalName and ActiveDirectoryRights WriteProperty, Kerberoasting of {tgt} can be enabled.'),
        'GPLink': (f'Checks whether the Group Policy Object {src} is linked to {tgt}. '
                   f'If the output returns a row showing GPO equal to {src} and LinkedTo equal to {tgt}, the policy applies to that scope.'),
        'ManageCA': (f'Checks whether {src} has Certificate Authority administrator rights. '
                     f'If the output returns {src} with ManageCA rights on the CA security descriptor, CA-wide configuration control is confirmed.'),
        'ManageCertificates': (f'Checks whether {src} can approve certificates on the Certificate Authority. '
                               f'If the output returns {src} with ManageCertificates rights, certificate requests can be approved or denied.'),
        'SyncLAPSPassword': (f'Checks whether {src} can write to the LAPS password attribute on {tgt}. '
                             f'If the output returns a row with ObjectType ms-Mcs-AdmPwd and ActiveDirectoryRights WriteProperty, the LAPS password can be overwritten.'),
        'AddMember': (f'Checks whether {src} can add members to the {tgt} group. '
                      f'If the output returns a row with ObjectType member and ActiveDirectoryRights WriteProperty (or GenericWrite / GenericAll), members can be added.'),
        'AddSelf': (f'Checks whether {src} has Self rights on the {tgt} group. '
                    f'If the output returns a row with ActiveDirectoryRights containing Self, self-enrolment into the group is possible.'),
        'ChangePassword': (f'Checks whether {src} has the User-Change-Password right on {tgt}. '
                           f'If the output returns a row with ActiveDirectoryRights containing ExtendedRight and ObjectType User-Change-Password, the password can be changed (with knowledge of the current password).'),
        'Contains': (f'{tgt} sits inside {src}. Permissions set on the container are inherited by all objects within it. '
                     f'No script needed; this is an AD structural relationship.'),
        'DumpSMSAPassword': (f'Checks whether {src} is listed as a principal allowed to retrieve the managed password of {tgt}. '
                             f'If the output returns a row with ServiceAccount equal to {tgt} and Principal matching {src}, the password can be retrieved.'),
        'ExecuteDCOM': (f'Checks whether {src} is in the Distributed COM Users group on {tgt}. '
                        f'If the listed group members include {src} or a group {src} belongs to, remote application execution is confirmed.'),
        'SQLAdmin': (f'SQL admin rights on {tgt} require direct access to the SQL Server to verify. '
                     f'If {src} or a group {src} belongs to appears in the sysadmin role on that instance, the privilege is confirmed.'),
        'WriteAccountRestrictions': (f'Checks whether {src} can modify account restriction attributes on {tgt}. '
                                     f'If the output returns a row with ObjectType userAccountControl (or related restriction attributes) and ActiveDirectoryRights WriteProperty, account control flags can be changed.'),
        'MemberOfLocalGroup': (f'This reflects local group membership on {tgt} that is not easily queried remotely, so verification is done on the target machine itself. '
                               f'If {src} or a group {src} belongs to appears in the relevant local group on {tgt}, the membership is confirmed.'),
        'RemoteInteractiveLogonRight': (f'Checks whether {src} has been granted the Remote Desktop logon right on {tgt}, typically via Group Policy. '
                                        f'If {src} or a group {src} belongs to is listed in the Allow log on through Remote Desktop Services user right, remote interactive logon is confirmed.'),
        'AddAllowedToAct': (f'Checks whether {src} can write to the msDS-AllowedToActOnBehalfOfOtherIdentity attribute on {tgt}. '
                            f'If the output returns a row with ObjectType msDS-AllowedToActOnBehalfOfOtherIdentity and ActiveDirectoryRights WriteProperty, resource-based constrained delegation can be configured.'),
        'CoerceAndRelayNTLMToSMB': (f'Checks the conditions that allow {src} to coerce authentication from {tgt} and relay it to an SMB service. '
                                    f'If SMB signing is not required on the target service and {tgt} can be coerced to authenticate (for example via the Print Spooler or WebClient service), the relay attack is possible.'),
        'CoerceAndRelayNTLMToLDAP': (f'Checks the conditions that allow {src} to coerce authentication from {tgt} and relay it to LDAP on a domain controller. '
                                     f'If LDAP signing is not enforced on the domain controller and {tgt} can be coerced to authenticate, the relay attack is possible.'),
        'CoerceAndRelayNTLMToLDAPS': (f'Checks the conditions that allow {src} to coerce authentication from {tgt} and relay it to LDAPS on a domain controller. '
                                      f'If LDAP channel binding is not enforced on the domain controller and {tgt} can be coerced to authenticate, the relay attack is possible.'),
        'AbuseTGTDelegation': (f'Checks whether {src} is configured for unconstrained delegation. '
                               f'If the output shows TrustedForDelegation set to True, any user who authenticates to {src} leaves a reusable Ticket Granting Ticket that can be captured.'),
        'CrossForestTrust': (f'Checks the trust relationship between {src} and {tgt}. '
                             f'If a forest trust exists and SID filtering or selective authentication is not enforced, principals from one forest can authenticate to resources in the other.'),
        'LocalAdminRequired': (f'Checks whether {src} has local administrator rights on {tgt}, as reported by SCCM. '
                               f'If {src} or a group {src} belongs to appears in the local Administrators group on {tgt}, administrative access is confirmed.'),
        'CoerceAndRelayToSMB': (f'Checks the conditions that allow authentication from {tgt} to be coerced and relayed to an SMB service, as identified through SCCM relay analysis. '
                                f'If SMB signing is not required on the target service and {tgt} can be coerced to authenticate, the relay attack is possible.'),
        'CoerceAndRelayToMSSQL': (f'Checks the conditions that allow authentication from {tgt} to be coerced and relayed to a SQL Server, as identified through SCCM relay analysis. '
                                  f'If the SQL Server does not require Extended Protection for Authentication and {tgt} can be coerced to authenticate, the relay attack is possible.'),
        'CoerceAndRelayToAdminService': (f'Checks the conditions that allow authentication from {tgt} to be coerced and relayed to the SCCM AdminService API. '
                                         f'If the AdminService does not require Extended Protection for Authentication and {tgt} can be coerced to authenticate, the relay attack is possible.'),
        'CoerceAndRelayToADCS': (f'Checks the conditions that allow authentication from {tgt} to be coerced and relayed to the Certificate Authority web enrolment endpoint. '
                                 f'If the CA does not require Extended Protection for Authentication and {tgt} can be coerced to authenticate, a login certificate can be obtained for the coerced account.'),
    }

    result = explanations.get(edge)
    if not result:
        if edge and edge.startswith('ADCSESC'):
            result = (f'Checks the certificate services configuration related to {edge} on {tgt}. '
                      f'If the output returns a row flagging the misconfiguration for {tgt} (for example the vulnerable template, overly permissive CA flag, or missing security extension), the issue is confirmed.')
        else:
            result = (f'Checks the relationship between {src} and {tgt}. '
                      f'If the output returns a row naming {src} with rights on {tgt}, the relationship is confirmed.')

    # split "X. If Y, Z." into intro + success condition
    m = re.match(r'(.+?\.)\s+If\s+(.+?),\s*(.+?)\.?\s*$', result, re.DOTALL)
    if m:
        return {'intro': _h(m.group(1)), 'confirmed_if': _h(m.group(2))}
    return {'intro': _h(result), 'confirmed_if': None}



def _h(text):
    return html.escape(str(text))


def _fmt_timestamp(ts):
    if ts is None or ts in ('Never', 'Unknown', '', -1, 0):
        return 'Never' if ts in (-1, 0, 'Never') else 'Unknown'
    try:
        return datetime.fromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError, OSError):
        return 'Unknown'


def _fmt_groups(groups):
    if not groups:
        return ''
    parts = []
    for g in groups:
        if not g:
            continue
        name = str(g).split('@')[0]
        if name.upper() in HIGH_VALUE_GROUPS_UPPER:
            parts.append(f'<strong>{_h(name)}</strong>')
        else:
            parts.append(_h(name))
    return ', '.join(parts)


_CATEGORIES = {
# (sev_key, css_class, badge_label, svg_source_label, display_name)
    "Non-admin Users with Escalation Paths": ("Critical", "critical", "CRITICAL", "Users", "Users with Escalation Paths"),
    "Computers with Escalation Paths":       ("High",     "high",     "HIGH",     "Computers", "Computers with Escalation Paths"),
}


def _severity(category):
    entry = _CATEGORIES.get(category)
    if entry:
        return entry[1], entry[2]
    return 'medium', 'MEDIUM'


CSS = r"""
:root {
    --primary-orange: #E87722;
    --primary-navy: #1B2A4A;
    --primary-slate: #345367;
    --gold: #B89968;
    --off-white: #F5F5F5;
    --white: #FFFFFF;
    --chestnut: #C62828;
    --denim: #5A6878;
    --platinum: #E0E0E0;
    --gray: #DDDDDD;

    --critical: #C62828;
    --high: #E87722;
    --medium: #F39C12;
    --safe-green: #2E7D32;

    --code-bg: #1a1d23;
    --code-fg: #c9d1d9;
}
*, *::before, *::after { box-sizing: border-box; }
body {
    font-family: Arial, sans-serif;
    background: var(--off-white);
    color: var(--primary-navy);
    margin: 0; padding: 0;
    line-height: 1.6;
}
.container { max-width: 1100px; margin: 0 auto; padding: 32px 24px 60px; }

#logo-container { text-align: center; margin-bottom: 20px; }
#logo-container img { max-width: 200px; height: auto; }

/* --- Header --- */
.report-header {
    border-bottom: 3px solid var(--primary-orange);
    padding-bottom: 16px; margin-bottom: 24px;
}
.report-header h1 {
    font-size: 1.6rem; color: var(--primary-navy); margin: 0 0 4px;
}
.report-header .meta {
    color: var(--denim); font-size: 0.85rem; margin: 0;
}


/* --- Section headings --- */
h2 {
    font-size: 1.2rem; color: var(--primary-slate); margin: 32px 0 6px;
    border-bottom: 2px solid var(--platinum); padding-bottom: 6px;
}
h2 .badge { vertical-align: middle; }

/* --- Badges --- */
.badge {
    display: inline-block; padding: 2px 8px; border-radius: 3px;
    font-weight: 700; font-size: 0.7rem; color: var(--white); margin-right: 6px;
    letter-spacing: 0.3px;
}
.badge.critical { background: var(--critical); }
.badge.high { background: var(--high); }
.badge.medium { background: var(--medium); color: var(--primary-navy); }

/* --- Cards --- */
.card {
    background: var(--white); border: 1px solid var(--platinum);
    border-radius: 6px; margin: 12px 0; padding: 16px 18px;
    border-left: 4px solid var(--platinum);
    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
}
.card.critical { border-left-color: var(--critical); }
.card.high { border-left-color: var(--high); }
.card h3 {
    font-size: 0.95rem; margin: 0 0 8px; color: var(--primary-navy);
    line-height: 1.4;
}
.count-badge {
    background: var(--platinum); color: var(--primary-navy); padding: 1px 7px;
    border-radius: 10px; font-size: 0.75rem; font-weight: 600;
    white-space: nowrap;
}

/* --- Path graph (SVG) --- */
.path-graph {
    overflow-x: auto; margin: 10px 0; padding: 6px 0;
    background: var(--primary-navy); border-radius: 5px;
}
.path-graph svg { display: block; }
.path-graph .pg-node {
    fill: var(--primary-slate); rx: 6; ry: 6;
    stroke: #4a6a7d; stroke-width: 1;
}
.path-graph .pg-node-src { fill: #2c3e50; stroke: var(--gold); stroke-width: 1.5; }
.path-graph .pg-node-dst { fill: var(--chestnut); stroke: var(--primary-orange); stroke-width: 1.5; }
.path-graph .pg-label {
    fill: var(--white); font-family: Arial, sans-serif; font-size: 11px;
    dominant-baseline: central; text-anchor: middle; pointer-events: none;
}
.path-graph .pg-type {
    fill: var(--platinum); font-family: Arial, sans-serif; font-size: 9px;
    dominant-baseline: central; text-anchor: middle; pointer-events: none;
    opacity: 0.8;
}
.path-graph .pg-edge { stroke: var(--primary-orange); stroke-width: 2; fill: none; }
.path-graph .pg-edge-label {
    fill: var(--gold); font-family: Arial, sans-serif; font-size: 9.5px;
    dominant-baseline: auto; text-anchor: middle;
}
.path-graph .edge-tip:hover .pg-edge-label { fill: var(--primary-orange); }
.path-graph .pg-arrow { fill: var(--primary-orange); }
.path-graph g.ent-hover { cursor: pointer; }
.path-graph g.ent-hover:hover .pg-node-dst { stroke: var(--gold); stroke-width: 2.5; }
.path-graph g.ent-hover:hover .pg-node-src { stroke: var(--gold); stroke-width: 2.5; }

/* --- Details / collapsibles --- */
details { margin: 6px 0; }
details > summary {
    cursor: pointer; font-weight: 600; font-size: 0.88rem;
    padding: 5px 0; user-select: none; color: var(--primary-slate);
}
details > summary:hover { color: var(--primary-orange); }
details[open] > summary { color: var(--primary-orange); }
.info-section { margin: 6px 0 6px 12px; }
.info-section h4 { margin: 0 0 2px; font-size: 0.88rem; color: var(--primary-navy); }
.info-section p { margin: 0 0 6px; font-size: 0.85rem; color: var(--primary-navy); line-height: 1.5; }

/* --- Code blocks --- */
.code-wrap { position: relative; }
.code-wrap .copy-btn {
    position: absolute; top: 6px; right: 6px;
    background: var(--primary-slate); color: var(--white);
    border: none; border-radius: 3px; padding: 3px 8px;
    font-size: 0.7rem; cursor: pointer; opacity: 0.5;
    transition: opacity 0.15s;
}
.code-wrap:hover .copy-btn { opacity: 1; }
.code-wrap .copy-btn.copied { background: var(--safe-green); opacity: 1; }
pre.ps-cmd {
    background: var(--code-bg); color: var(--code-fg);
    padding: 12px 14px; border-radius: 4px; overflow-x: auto;
    font-size: 0.78rem; line-height: 1.5; white-space: pre-wrap;
    word-break: break-all; margin: 6px 0 10px;
}

/* --- Entity lists --- */
.entity-list {
    max-height: 260px; overflow-y: auto; font-size: 0.82rem;
    margin: 4px 0; padding-left: 18px; color: var(--primary-navy);
}
.entity-list li { margin-bottom: 1px; }
.entity-list-status {
    font-size: 0.82rem; color: var(--denim); margin: 4px 0 4px 12px;
}
.ent-hover {
    cursor: default; border-bottom: 1px dotted var(--denim);
}
#ent-tooltip {
    display: none; position: fixed;
    background: var(--white); border: 1px solid var(--platinum);
    border-radius: 4px; padding: 8px 10px; z-index: 200;
    font-size: 0.78rem; line-height: 1.5; white-space: normal; word-wrap: break-word;
    box-shadow: 0 3px 8px rgba(0,0,0,0.12); color: var(--primary-navy);
    pointer-events: auto; max-width: 420px; max-height: 360px;
    width: max-content; overflow-y: auto;
}

/* --- Tabs --- */
.tab-bar {
    display: flex; background: var(--primary-navy); border-radius: 4px 4px 0 0;
    margin: 20px 0 0; overflow: hidden;
}
.tab-btn {
    padding: 12px 22px; cursor: pointer; font-weight: 600; font-size: 0.9rem;
    border: none; background: transparent; color: var(--white);
    transition: background 0.15s;
}
.tab-btn:hover { background: rgba(232,119,34,0.18); }
.tab-btn.active { background: var(--primary-orange); color: var(--primary-navy); }
.tab-pane { display: none; }
.tab-pane.active { display: block; }
.tab-hint {
    font-size: 0.8rem; color: var(--denim); margin: 6px 2px 0;
}

/* --- Layout: sticky sidebar + content --- */
.report-layout {
    display: grid; grid-template-columns: 270px minmax(0, 1fr);
    gap: 18px; align-items: start; margin-top: 14px;
}
.path-sidebar {
    position: sticky; top: 12px;
    max-height: calc(100vh - 60px); overflow-y: auto;
    background: var(--white); border: 1px solid var(--platinum);
    border-radius: 6px; padding: 12px 12px 14px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.06);
}
.path-sidebar h4 {
    margin: 0 0 8px; font-size: 0.85rem; letter-spacing: 0.4px;
    text-transform: uppercase; color: var(--primary-slate);
}
.sidebar-filter {
    width: 100%; padding: 6px 8px; font-size: 0.82rem;
    border: 1px solid var(--platinum); border-radius: 4px; margin: 0 0 10px;
    color: var(--primary-navy); background: var(--off-white);
}
.sidebar-filter:focus { outline: none; border-color: var(--primary-orange); }
.sidebar-list { list-style: none; margin: 0; padding: 0; }
.sidebar-row {
    border-radius: 4px; margin-bottom: 2px;
}
.sidebar-row a {
    display: block; padding: 7px 9px; text-decoration: none;
    color: var(--primary-navy); font-size: 0.82rem; line-height: 1.35;
    border-left: 3px solid transparent;
}
.sidebar-row a:hover { background: var(--off-white); }
.sidebar-row.active a {
    background: rgba(232,119,34,0.10);
    border-left-color: var(--primary-orange);
}
.sidebar-row .sev-dot {
    display: inline-block; width: 8px; height: 8px; border-radius: 50%;
    background: var(--platinum); margin-right: 6px; vertical-align: middle;
}
.sidebar-row.critical .sev-dot { background: var(--critical); }
.sidebar-row.high .sev-dot { background: var(--high); }
.sidebar-row.medium .sev-dot { background: var(--medium); }
.sidebar-row .step-count {
    font-weight: 700; color: var(--primary-slate); margin-right: 4px;
}
.sidebar-row .dest-label {
    color: var(--primary-navy); word-break: break-word;
}
.sidebar-row .affected-count {
    display: block; margin-top: 2px; padding-left: 14px;
    font-size: 0.74rem; color: var(--denim);
}
.sidebar-empty {
    padding: 8px 4px; font-size: 0.8rem; color: var(--denim); font-style: italic;
}

/* Highlight pulse when a card is jumped to */
@keyframes card-flash {
    0% { box-shadow: 0 0 0 0 rgba(232,119,34,0.55); }
    100% { box-shadow: 0 0 0 6px rgba(232,119,34,0); }
}
.card.flash { animation: card-flash 1.4s ease-out; }

@media (max-width: 960px) {
    .report-layout { grid-template-columns: 1fr; }
    .path-sidebar {
        position: static; max-height: 280px;
    }
}

/* --- Stat cards --- */
.stat-row {
    display: flex; gap: 16px; margin-bottom: 6px;
}
.stat-card {
    flex: 1; background: var(--white); border: 1px solid var(--platinum);
    border-radius: 6px; padding: 18px 14px; text-align: center;
    border-top: 3px solid var(--critical);
    box-shadow: 0 1px 3px rgba(0,0,0,0.06);
}
.stat-number {
    font-size: 2.2rem; font-weight: 800; color: var(--critical);
    line-height: 1.1; margin-bottom: 2px;
}
.stat-label {
    font-size: 0.95rem; font-weight: 600; color: var(--primary-navy);
}

.ps-context {
    background: var(--gray); border-left: 3px solid var(--gold);
    padding: 8px 12px; margin: 8px 0 4px; font-size: 0.82rem;
    color: var(--primary-navy); border-radius: 0 4px 4px 0;
}

.hidden { display: none !important; }

.step-header {
    font-weight: 600; font-size: 0.85rem; margin: 10px 0 4px;
    color: var(--primary-navy);
}

.step-intro {
    background: var(--off-white); border-left: 3px solid var(--primary-slate);
    padding: 8px 12px; margin: 4px 0; font-size: 0.82rem;
    color: var(--primary-navy); border-radius: 0 4px 4px 0;
}
.step-intro strong { color: var(--primary-slate); }

.step-confirm {
    background: #EAF3ED; border-left: 3px solid #2E7D32;
    padding: 8px 12px; margin: 4px 0 12px; font-size: 0.82rem;
    color: var(--primary-navy); border-radius: 0 4px 4px 0;
}
.step-confirm strong { color: #2E7D32; }

/* --- Confidential footer --- */
.conf-footer {
    position: fixed; bottom: 0; left: 0; width: 100%;
    background: var(--primary-navy); color: var(--white);
    text-align: center; padding: 7px 0; font-size: 0.75rem;
    font-weight: 600; letter-spacing: 0.5px; z-index: 100;
}

/* --- Print --- */
@media print {
    body { background: #fff; }
    .conf-footer { display: none; }
    details[open] > summary ~ * { display: block; }
    pre.ps-cmd { font-size: 0.68rem; background: #f5f5f5; color: #222; }
    .card { page-break-inside: avoid; box-shadow: none; border: 1px solid #ccc; }
    .report-layout { display: block; }
    .path-sidebar, .tab-bar, .tab-hint, .sidebar-filter { display: none; }
}
"""

JS = r"""
document.addEventListener('DOMContentLoaded', function() {
    /* --- Tabs --- */
    document.querySelectorAll('.tab-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
            var target = this.getAttribute('data-tab');
            document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
            document.querySelectorAll('.tab-pane').forEach(function(p) { p.classList.remove('active'); });
            // Drop any active highlight from the leaving pane so the new pane starts fresh
            // (scroll-spy repopulates on next intersection event).
            document.querySelectorAll('.sidebar-row.active').forEach(function(r) { r.classList.remove('active'); });
            this.classList.add('active');
            var pane = document.getElementById(target);
            if (pane) pane.classList.add('active');
        });
    });

    /* --- Sidebar: click row, smooth-scroll + flash the card --- */
    document.querySelectorAll('.sidebar-row a').forEach(function(link) {
        link.addEventListener('click', function(e) {
            var href = link.getAttribute('href') || '';
            if (!href.startsWith('#')) return;
            var card = document.getElementById(href.slice(1));
            if (!card) return;
            e.preventDefault();
            card.scrollIntoView({behavior: 'smooth', block: 'start'});
            card.classList.remove('flash');
            // Force reflow so the animation restarts on consecutive clicks.
            void card.offsetWidth;
            card.classList.add('flash');
        });
    });

    /* --- Sidebar: filter rows by destination name --- */
    document.querySelectorAll('.sidebar-filter').forEach(function(input) {
        input.addEventListener('input', function() {
            var needle = input.value.trim().toLowerCase();
            var sidebar = input.closest('.path-sidebar');
            var rows = sidebar.querySelectorAll('.sidebar-row');
            rows.forEach(function(row) {
                var label = row.getAttribute('data-label') || '';
                row.style.display = (!needle || label.indexOf(needle) !== -1) ? '' : 'none';
            });
            // If the active row got filtered out, drop the highlight so we don't sit on a hidden row.
            var active = sidebar.querySelector('.sidebar-row.active');
            if (active && active.style.display === 'none') {
                active.classList.remove('active');
            }
        });
    });

    /* --- Sidebar: scroll-spy: highlight the row whose card is most prominent --- */
    var sidebarRowsByTarget = {};
    document.querySelectorAll('.sidebar-row').forEach(function(row) {
        var t = row.getAttribute('data-target');
        if (t) sidebarRowsByTarget[t] = row;
    });

    function pickActiveRow(ratios) {
        // Walk visible cards in descending intersection order; pick the first row
        // that is in the active tab pane and not hidden by the filter.
        var sortedIds = Object.keys(ratios).sort(function(a, b) { return ratios[b] - ratios[a]; });
        for (var i = 0; i < sortedIds.length; i++) {
            var row = sidebarRowsByTarget[sortedIds[i]];
            if (!row) continue;
            if (row.style.display === 'none') continue;
            var pane = row.closest('.tab-pane');
            if (pane && !pane.classList.contains('active')) continue;
            return row;
        }
        return null;
    }

    function keepActiveInSidebarView(row) {
        // The sidebar has its own scroll container (max-height: calc(100vh - 60px) +
        // overflow-y: auto). On long reports the active row can drift off-screen
        // inside that container, so nudge sidebar.scrollTop just enough to put it back
        // in view. Manual math instead of scrollIntoView so we don't scroll the page.
        var sidebar = row.closest('.path-sidebar');
        if (!sidebar) return;
        var sRect = sidebar.getBoundingClientRect();
        var rRect = row.getBoundingClientRect();
        if (rRect.top < sRect.top + 8) {
            sidebar.scrollTop += rRect.top - sRect.top - 12;
        } else if (rRect.bottom > sRect.bottom - 8) {
            sidebar.scrollTop += rRect.bottom - sRect.bottom + 12;
        }
    }

    if (window.IntersectionObserver && Object.keys(sidebarRowsByTarget).length) {
        var visibleRatios = {};
        var spy = new IntersectionObserver(function(entries) {
            entries.forEach(function(entry) {
                if (entry.isIntersecting) {
                    visibleRatios[entry.target.id] = entry.intersectionRatio;
                } else {
                    delete visibleRatios[entry.target.id];
                }
            });
            var topRow = pickActiveRow(visibleRatios);
            document.querySelectorAll('.sidebar-row.active').forEach(function(r) { r.classList.remove('active'); });
            if (topRow) {
                topRow.classList.add('active');
                keepActiveInSidebarView(topRow);
            }
        }, {rootMargin: '-25% 0px -55% 0px', threshold: [0, 0.25, 0.5, 0.75, 1]});
        document.querySelectorAll('.path-card').forEach(function(card) { spy.observe(card); });
    }

    /* --- Copy buttons on code blocks --- */
    document.querySelectorAll('pre.ps-cmd').forEach(function(pre) {
        var wrap = document.createElement('div');
        wrap.className = 'code-wrap';
        pre.parentNode.insertBefore(wrap, pre);
        wrap.appendChild(pre);
        var btn = document.createElement('button');
        btn.className = 'copy-btn';
        btn.textContent = 'Copy';
        btn.addEventListener('click', function() {
            navigator.clipboard.writeText(pre.textContent).then(function() {
                btn.textContent = 'Copied';
                btn.classList.add('copied');
                setTimeout(function() { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 1500);
            });
        });
        wrap.appendChild(btn);
    });

    /* --- Embedded report data / lazy affected-entity rendering --- */
    var reportData = { entities: {}, groupSets: [], pathGroups: {}, highValueGroups: [] };
    var reportDataEl = document.getElementById('report-data');
    if (reportDataEl) {
        try {
            reportData = JSON.parse(reportDataEl.textContent || '{}');
        } catch (err) {
            reportData = { entities: {}, groupSets: [], pathGroups: {}, highValueGroups: [] };
        }
    }

    var highValueGroups = {};
    (reportData.highValueGroups || []).forEach(function(groupName) {
        highValueGroups[String(groupName).toUpperCase()] = true;
    });

    function escapeHtml(value) {
        return String(value == null ? '' : value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;');
    }

    function formatGroups(groups) {
        if (!groups || !groups.length) return '';
        var parts = [];
        groups.forEach(function(groupName) {
            if (!groupName) return;
            var cleanName = String(groupName).split('@')[0];
            var escapedName = escapeHtml(cleanName);
            if (highValueGroups[cleanName.toUpperCase()]) {
                parts.push('<strong>' + escapedName + '</strong>');
            } else {
                parts.push(escapedName);
            }
        });
        return parts.join(', ');
    }

    function buildEntityTooltip(entityName, entityData) {
        if (!entityData) return '';
        var rows = ['<strong>Username:</strong> ' + escapeHtml(entityName)];

        if (entityData.description) {
            rows.push('<strong>Description:</strong> ' + escapeHtml(entityData.description));
        }
        if (entityData.enabled !== null && entityData.enabled !== undefined) {
            rows.push('<strong>Enabled:</strong> ' + (entityData.enabled ? 'Yes' : 'No'));
        }

        rows.push('<strong>Admin:</strong> ' + (entityData.isAdmin ? 'Yes' : 'No'));
        rows.push('<strong>Privileged:</strong> ' + (entityData.isPrivileged ? 'Yes' : 'No'));

        if (entityData.lastLogon) {
            rows.push('<strong>Last Logon:</strong> ' + escapeHtml(entityData.lastLogon));
        }
        if (entityData.passwordLastChanged) {
            rows.push('<strong>Password Last Changed:</strong> ' + escapeHtml(entityData.passwordLastChanged));
        }

        var groups = [];
        if (entityData.groupSet !== null && entityData.groupSet !== undefined) {
            groups = (reportData.groupSets || [])[entityData.groupSet] || [];
        }
        var groupsHtml = formatGroups(groups);
        if (groupsHtml) {
            rows.push('<strong>Groups:</strong> ' + groupsHtml);
        }

        return rows.join('<br>');
    }

    function resolveTooltipHtml(el) {
        var staticTip = el.getAttribute('data-tip');
        if (staticTip) return staticTip;

        var entityKey = el.getAttribute('data-entity-key');
        if (!entityKey) return '';

        var entityData = (reportData.entities || {})[entityKey];
        return buildEntityTooltip(el.textContent || entityKey, entityData);
    }

    function renderEntityList(detailsEl) {
        if (!detailsEl || detailsEl.getAttribute('data-loaded') === '1') return;

        var cardId = detailsEl.getAttribute('data-card-id');
        var groupData = (reportData.pathGroups || {})[cardId] || {};
        var entities = groupData.entities || [];
        var list = detailsEl.querySelector('.lazy-entity-list');
        var status = detailsEl.querySelector('.entity-list-status');
        if (!list) return;

        var fragment = document.createDocumentFragment();
        entities.forEach(function(entityName) {
            var li = document.createElement('li');
            var entityKey = String(entityName).toLowerCase();
            if ((reportData.entities || {})[entityKey]) {
                var span = document.createElement('span');
                span.className = 'ent-hover';
                span.setAttribute('data-entity-key', entityKey);
                span.textContent = entityName;
                li.appendChild(span);
            } else {
                li.textContent = entityName;
            }
            fragment.appendChild(li);
        });

        list.textContent = '';
        list.appendChild(fragment);
        if (status) status.classList.add('hidden');
        detailsEl.setAttribute('data-loaded', '1');
    }

    document.querySelectorAll('details.affected-entities').forEach(function(detailsEl) {
        detailsEl.addEventListener('toggle', function() {
            if (detailsEl.open) renderEntityList(detailsEl);
        });
        if (detailsEl.open) renderEntityList(detailsEl);
    });

    window.addEventListener('beforeprint', function() {
        document.querySelectorAll('details.affected-entities').forEach(function(detailsEl) {
            detailsEl.open = true;
            renderEntityList(detailsEl);
        });
    });

    /* --- Entity tooltip (fixed-position, follows mouse) --- */
    var tip = document.createElement('div');
    tip.id = 'ent-tooltip';
    document.body.appendChild(tip);
    var activeHover = null;

    document.addEventListener('mousemove', function(e) {
        var el = e.target.closest('.ent-hover');
        var inTip = e.target.closest('#ent-tooltip');
        if (el) {
            if (el !== activeHover) {
                activeHover = el;
                tip.innerHTML = resolveTooltipHtml(el);
                tip.scrollTop = 0;
            }
            if (!tip.innerHTML) {
                tip.style.display = 'none';
                return;
            }
            tip.style.display = 'block';
            var x = e.clientX + 14, y = e.clientY + 14;
            if (x + tip.offsetWidth > window.innerWidth - 10) x = e.clientX - tip.offsetWidth - 10;
            if (y + tip.offsetHeight > window.innerHeight - 10) y = e.clientY - tip.offsetHeight - 10;
            tip.style.left = x + 'px';
            tip.style.top = y + 'px';
        } else if (inTip) {
            // Pointer is inside the tooltip (e.g. scrolling the group list) — keep it visible.
        } else if (activeHover) {
            activeHover = null;
            tip.style.display = 'none';
        }
    });

});
"""


class ClientReportGenerator:

    def __init__(self, json_path=None, json_data=None):
        if json_data is not None:
            self.data = json_data
        else:
            with open(json_path, 'r', encoding='utf-8-sig') as f:
                self.data = json.load(f)

        meta = self.data.get('metadata', {})
        self.domain = meta.get('domain', 'UNKNOWN')
        self.domain_controller = meta.get('enabled_dc_fqdn')
        self.domain_sid = meta.get('domain_sid')
        self.destination_groups = self.data.get('destination_groups', {})
        self.entities = self.data.get('entities', [])
        self.domain_summary = self.data.get('domain_summary', {})
        self._path_steps_cache = {}
        self._client_report_data = None

    def generate(self, output_path):
        html_content = self._build_html()
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"AD report generated: {output_path}")


    def _build_entity_lookup(self):
        lookup = {}
        for ent in self.entities:
            if not isinstance(ent, dict):
                continue
            name = (ent.get('name') or '').lower()
            if name:
                lookup[name] = ent
        return lookup

    def _get_path_steps(self, path_string):
        if path_string not in self._path_steps_cache:
            self._path_steps_cache[path_string] = _parse_path_string(path_string)
        return self._path_steps_cache[path_string]

    @staticmethod
    def _path_card_id(category, path_string):
        key = f'{category}\0{path_string}'
        return 'p-' + hashlib.md5(key.encode()).hexdigest()[:10]

    @staticmethod
    def _json_script_content(data):
        return json.dumps(data, ensure_ascii=False, separators=(',', ':')).replace('</', '<\\/')

    def _build_client_entity_data(self):
        entity_data = {}
        group_sets = []
        group_set_ids = {}

        for ent in self.entities:
            if not isinstance(ent, dict):
                continue
            name = ent.get('name')
            if not name:
                continue

            desc = ent.get('description') or ''
            if desc.strip() == _DEFAULT_DESCRIPTION:
                desc = ''

            groups = ent.get('groups')
            if not groups:
                groups = self._entity_groups.get(name.lower(), [])
            group_key = tuple(str(g) for g in groups or [] if g)
            group_set_id = None
            if group_key:
                group_set_id = group_set_ids.get(group_key)
                if group_set_id is None:
                    group_set_id = len(group_sets)
                    group_set_ids[group_key] = group_set_id
                    group_sets.append(list(group_key))

            last_logon = ent.get('lastLogon')
            pwd_changed = ent.get('passwordLastChanged')

            entity_data[name.lower()] = {
                'description': desc,
                'enabled': ent.get('enabled'),
                'isAdmin': bool(ent.get('isAdmin')),
                'isPrivileged': bool(ent.get('isPrivileged')),
                'lastLogon': _fmt_timestamp(last_logon) if last_logon not in (None, '') else '',
                'passwordLastChanged': _fmt_timestamp(pwd_changed) if pwd_changed not in (None, '') else '',
                'groupSet': group_set_id,
            }

        return entity_data, group_sets

    def _build_path_caches(self):
        entity_groups = {}   # name_lower -> sorted list of group names
        dest_cache = {}      # dest_node_name -> info dict

        type_priority = ['User', 'Computer', 'Group', 'GPO', 'OU', 'Domain',
                         'Container', 'CertTemplate', 'EnterpriseCA',
                         'AIACA', 'RootCA', 'NTAuthStore', 'IssuancePolicy']

        for entity in self.entities:
            name = entity.get('name')
            if not name:
                continue
            name_lower = name.lower()
            groups = set()

            for risk in entity.get('risks') or []:
                if not isinstance(risk, dict):
                    continue
                cat = risk.get('category')
                details = risk.get('details') or {}
                spn = details.get('shortest_path_names') or []

                for i in range(1, len(spn), 2):
                    if isinstance(spn[i], str) and spn[i] == 'MemberOf' and i + 1 < len(spn):
                        node = spn[i + 1]
                        if isinstance(node, dict):
                            gname = (node.get('name') or '').split('@')[0]
                            if gname:
                                groups.add(gname)

                if spn and isinstance(spn[-1], dict):
                    dest = spn[-1]
                    dname = dest.get('name') or ''
                    if dname and dname not in dest_cache:
                        labels = dest.get('labels') or []
                        obj_type = ''
                        for t in type_priority:
                            if t in labels:
                                obj_type = t
                                break
                        dn = dest.get('dn') or ''
                        dest_cache[dname] = {
                            'labels': labels,
                            'type': obj_type,
                            'dn': dn,
                            'sid': dest.get('objectid') or '',
                            'samaccountname': dest.get('samaccountname') or '',
                            'reason': self._get_high_value_reason(dname, obj_type, labels, dn),
                            'domain': dest.get('domain') or '',
                            'operatingsystem': dest.get('operatingsystem') or '',
                            'functionallevel': dest.get('functionallevel') or '',
                            'description': dest.get('description') or '',
                            'caname': dest.get('caname') or '',
                            'certname': dest.get('certname') or '',
                            'dnshostname': dest.get('dnshostname') or '',
                            'displayname': dest.get('displayname') or '',
                            'enabled': dest.get('enabled'),
                            'ca_active': dest.get('ca_active'),
                            'ca_template_count': dest.get('ca_template_count'),
                        }

            if groups:
                entity_groups[name_lower] = sorted(groups)

        return entity_groups, dest_cache

    def _build_what_narrative(self, steps, count, category, reason):
        if not steps:
            return ''

        is_users = 'Users' in category
        plural = count != 1
        if count == 1:
            subject = 'This user' if is_users else 'This computer'
        else:
            subject = f'{count} users' if is_users else f'{count} computers'

        dest_name = steps[-1]['node']
        dest_type = steps[-1]['node_type'] or 'object'
        dest_reason = f' ({reason.lower()})' if reason else ''

        are = 'are' if plural else 'is'
        member_word = 'members' if plural else 'a member'
        they = 'they' if plural else 'it'

        # only LEADING MemberOf steps — the subject's own memberships, not the attack chain
        groups = []
        chain_start = 0
        for i, s in enumerate(steps):
            if s['edge'] == 'MemberOf':
                groups.append(s['node'])
                chain_start = i + 1
            else:
                break

        final_edge = None
        final_node = None
        final_type = None
        for s in reversed(steps):
            if s['edge'] and s['edge'] != 'MemberOf':
                final_edge = s['edge']
                final_node = s['node']
                final_type = s['node_type'] or 'object'
                break
            elif s['edge'] == 'MemberOf' and steps.index(s) >= chain_start:
                # MemberOf past chain_start is part of the attack chain, not subject membership
                final_edge = s['edge']
                final_node = s['node']
                final_type = s['node_type'] or 'object'
                break

        # path is all MemberOf — just group joining
        if not final_edge:
            if len(groups) == 1:
                return (f'{_h(subject)} {are} {member_word} of the {_h(groups[0])} group{dest_reason}. '
                        f'All members of this group inherit its permissions.')
            elif len(groups) > 1:
                chain = ' which is a member of '.join(_h(g) for g in groups)
                return (f'{_h(subject)} {are} {member_word} of {chain}{dest_reason}. '
                        f'Permissions are inherited through this group chain.')
            return ''

        # "can" form works for both singular and plural subjects
        action_map = {
            'GenericAll': 'can fully control',
            'GenericWrite': 'can modify attributes on',
            'WriteDacl': 'can change the permissions of',
            'WriteOwner': 'can take ownership of',
            'Owns': 'can modify permissions on',
            'DCSync': 'can extract all password hashes from',
            'AdminTo': 'can administer',
            'CanRDP': 'can Remote Desktop into',
            'CanPSRemote': 'can run PowerShell remotely on',
            'ForceChangePassword': 'can reset the password of',
            'ReadLAPSPassword': 'can read the local admin password of',
            'ReadGMSAPassword': 'can read the service account password of',
            'AllowedToAct': 'can impersonate users on',
            'AllowedToDelegate': 'can delegate credentials to',
            'AddKeyCredential': 'can add shadow credentials to',
            'AddKeyCredentialLink': 'can add shadow credentials to',
            'CoerceAndRelayNTLMToADCS': 'can relay authentication to the Certificate Authority and obtain a certificate for',
            'CoerceToTGT': 'can coerce authentication from',
            'GoldenCert': 'can use the CA private key to forge certificates for',
            'AllExtendedRights': 'can reset passwords and read sensitive attributes on',
            'WriteGPLink': 'can link Group Policies to',
            'WriteSPN': 'can set service principal names on',
            'GPLink': 'can apply Group Policy settings to',
            'ManageCA': 'can administer the Certificate Authority on',
            'ManageCertificates': 'can approve certificates on',
            'SyncLAPSPassword': 'can overwrite the LAPS password of',
            'AddMember': 'can add members to',
            'AddSelf': 'can add itself to',
            'ChangePassword': 'can change the password of',
            'MemberOf': 'which is a member of',
            'Contains': 'contains',
            'DumpSMSAPassword': 'can dump the managed password of',
            'ExecuteDCOM': 'can execute remote applications on',
            'SQLAdmin': 'can run commands on',
            'WriteAccountRestrictions': 'can modify account restrictions on',
            'HasSession': 'can harvest credentials from a logged-in session of',
            'AddAllowedToAct': 'can configure resource-based constrained delegation on',
            'CoerceAndRelayNTLMToSMB': 'can coerce authentication and relay it via SMB to',
            'CoerceAndRelayNTLMToLDAP': 'can coerce authentication and relay it via LDAP to compromise',
            'CoerceAndRelayNTLMToLDAPS': 'can coerce authentication and relay it via LDAPS to compromise',
            'HasSIDHistory': 'inherits the access of',
            'AbuseTGTDelegation': 'can capture a Ticket Granting Ticket from',
            'CrossForestTrust': 'can authenticate across the forest trust to',
            'LocalAdminRequired': 'has local administrator rights on',
            'CoerceAndRelayToSMB': 'can coerce authentication and relay it via SMB to',
            'CoerceAndRelayToMSSQL': 'can coerce authentication and relay it to the SQL Server on',
            'CoerceAndRelayToAdminService': 'can coerce authentication and relay it to the SCCM AdminService on',
            'CoerceAndRelayToADCS': 'can coerce authentication and relay it to the Certificate Authority on',
        }
        if final_edge in action_map:
            action = action_map[final_edge]
        elif final_edge and final_edge.startswith('ADCSESC'):
            action = f'can exploit a certificate services vulnerability ({final_edge}) on'
        else:
            has = 'have' if plural else 'has'
            action = f'{has} {final_edge} access to'

        if groups:
            if len(groups) == 1:
                group_part = f'{are} {member_word} of the {_h(groups[0])} group, which means {they}'
            else:
                chain = ', then '.join(_h(g) for g in groups)
                group_part = f'{are} {member_word} of {chain}, which means {they}'

            # intermediate steps after the leading MemberOf chain, excluding the final target
            mid_steps = [s for i, s in enumerate(steps) if i >= chain_start and s['edge'] and s['node'] != final_node]
            if mid_steps:
                chain_text = self._join_chain_steps(mid_steps, action_map)
                return (f'{_h(subject)} {group_part} {chain_text}, '
                        f'and from there {action} {_h(final_node)}{dest_reason}.')
            else:
                return (f'{_h(subject)} {group_part} '
                        f'{action} {_h(final_node)}{dest_reason}.')
        else:
            mid_steps = [s for s in steps if s['edge'] and s['node'] != final_node]
            if mid_steps:
                chain_text = self._join_chain_steps(mid_steps, action_map)
                if len(mid_steps) == 1:
                    return (f'{_h(subject)} {chain_text}, which means {they} '
                            f'{action} {_h(final_node)}{dest_reason}.')
                else:
                    return (f'{_h(subject)} {chain_text}, '
                            f'and from there {action} {_h(final_node)}{dest_reason}.')
            return (f'{_h(subject)} '
                    f'{action} {_h(final_node)}{dest_reason}.')

    @staticmethod
    def _join_chain_steps(mid_steps, action_map):
        parts = []
        for s in mid_steps:
            mid_action = action_map.get(s['edge'], f'have {s["edge"]} access to')
            parts.append((mid_action, _h(s['node']), s['edge'] == 'MemberOf'))

        result = f'{parts[0][0]} {parts[0][1]}'
        for action_text, node_text, is_memberof in parts[1:]:
            if is_memberof:
                result += f', {action_text} {node_text}'
            else:
                result += f', then {action_text} {node_text}'
        return result

    @staticmethod
    def _build_impact_sentence(final_edge, dest_name, dest_type, reason):
        dn = dest_name or 'the target'
        dt = (dest_type or '').lower()
        rl = (reason or '').lower()

        # any meaningful access to a DC = full domain compromise (LSASS dump, DCSync, krbtgt forging)
        DC_FULL_COMPROMISE_EDGES = {
            'GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'Owns',
            'AllExtendedRights', 'AdminTo', 'ReadLAPSPassword', 'SyncLAPSPassword',
            'AddKeyCredentialLink', 'AddKeyCredential', 'AllowedToAct',
            'AllowedToDelegate', 'AddAllowedToAct', 'WriteSPN',
            'WriteAccountRestrictions', 'ForceChangePassword', 'ChangePassword',
            'CoerceAndRelayNTLMToSMB', 'CoerceAndRelayNTLMToLDAP',
            'CoerceAndRelayNTLMToLDAPS',
            'LocalAdminRequired',
            'CoerceAndRelayToSMB', 'CoerceAndRelayToMSSQL',
            'CoerceAndRelayToAdminService', 'CoerceAndRelayToADCS',
        }
        if 'domain controller' in rl and final_edge in DC_FULL_COMPROMISE_EDGES:
            return (f'Because {dn} is a domain controller, this access leads to full domain compromise. '
                    f'An attacker could extract every password hash from the directory (including the '
                    f'krbtgt key needed to forge Kerberos tickets) and gain administrative control over '
                    f'every system and account in the domain.')

        # tier-zero non-DC hosts (ADCS, ADFS, AAD Connect, password vaults)
        if 'high-value server' in rl and final_edge in DC_FULL_COMPROMISE_EDGES:
            return (f'{dn} is a tier-zero asset. Compromise here gives access to credentials, '
                    f'certificates, configuration, or trust data that typically leads to full '
                    f'domain compromise.')

        edge_impact = {
            'GenericAll': {
                'user': f'An attacker could reset {dn}\'s password and log in as them, configure an alternative login method to access the account without the password, or if the account runs a service, crack its password offline.',
                'group': None,  # fall through to group_impacts lookup below
                'computer': f'An attacker could configure {dn} to allow them to impersonate any user who accesses it (including administrators), set up an alternative login to authenticate as the machine account, or use it to move to other systems on the network.',
                'ou': f'An attacker could reset passwords, change permissions, or deploy policies to every account and computer within the {dn} organizational unit.',
                'certtemplate': f'An attacker could modify this template to issue login certificates for any account, including Domain Admins.',
                'gpo': f'An attacker could edit this policy to run malicious scripts or change security settings on every system it applies to.',
                'container': f'An attacker could control every account and computer within the {dn} container, including resetting passwords and changing permissions on objects inside it.',
                'enterpriseca': f'An attacker who controls this Certificate Authority can issue trusted login certificates for any account, including Domain Admins, and that access survives password changes.',
                'domain': f'An attacker with full control of the domain object can grant themselves DCSync and other domain-wide privileges, leading to full domain compromise.',
                '_': f'An attacker could take over {dn} and use it to gain further access.',
            },
            'WriteDacl': {
                'user': f'An attacker could give themselves permission to reset {dn}\'s password and take over the account.',
                'group': f'An attacker could give themselves permission to join {dn} and inherit its access.',
                'ou': f'An attacker could grant themselves control over every account and computer in the {dn} organizational unit.',
                'gpo': f'An attacker could grant themselves rights to edit this policy and push scripts or security changes to every linked system.',
                'container': f'An attacker could grant themselves control over every account and computer within the {dn} container through inherited permissions.',
                'enterpriseca': f'An attacker could grant themselves CA management rights and issue login certificates for any account in the domain.',
                'certtemplate': f'An attacker could grant themselves enrolment rights and issue login certificates for privileged accounts.',
                'domain': f'An attacker could grant themselves DCSync or other domain-wide rights at the domain root, leading to full domain compromise.',
                '_': f'An attacker could grant themselves full control over {dn}.',
            },
            'WriteOwner': {
                'group': f'Once they own {dn}, they can rewrite its permissions to add themselves as a member and inherit the group\'s access.',
                'ou': f'Once they own it, they can control every account and computer in the {dn} organizational unit.',
                'gpo': f'Once they own it, they can edit the policy to affect every system it applies to.',
                'container': f'Once they own it, they can rewrite permissions on every account and computer within the {dn} container.',
                'enterpriseca': f'Once they own it, they can grant themselves CA management rights and issue certificates that log in as any account, including Domain Admins.',
                'certtemplate': f'Once they own it, they can reconfigure the template to issue login certificates for any account in the domain.',
                'domain': f'Once they own the domain object, they can rewrite its permissions and grant themselves domain-wide privileges such as DCSync.',
                '_': f'Once they own {dn}, they can grant themselves any permission on it.',
            },
            'GenericWrite': {
                'user': f'An attacker could modify {dn}\'s account to make it vulnerable to password cracking or configure it for impersonation.',
                'group': f'An attacker could write to the membership attribute on {dn} to add themselves and inherit the group\'s access.',
                'computer': f'An attacker could reconfigure {dn} to allow impersonation of other users connecting to it.',
                'gpo': f'An attacker could edit this policy to run scripts or change security settings on every linked system.',
                'ou': f'An attacker could modify properties of the {dn} organizational unit to affect objects within it.',
                'container': f'An attacker could modify properties on the {dn} container to affect inherited behaviour on every child object.',
                'enterpriseca': f'An attacker could modify the CA configuration to enable issuance of certificates for privileged accounts.',
                'certtemplate': f'An attacker could modify template flags or extensions to make it issue login certificates for any account.',
                'domain': f'An attacker could modify domain-level properties to weaken security or enable further attacks across the directory.',
                '_': f'An attacker could modify {dn}\'s properties to enable further attacks.',
            },
            'Owns': {
                'group': f'As the owner, they can rewrite permissions on {dn} to add themselves as a member and inherit the group\'s access.',
                'gpo': f'As the owner, they can rewrite the policy\'s permissions and edit it to push scripts or security changes to every linked system.',
                'ou': f'As the owner, they can rewrite the access list and gain control over every account and computer in the {dn} organizational unit.',
                'container': f'As the owner, they can rewrite the access list and gain control over every child object within the {dn} container through inheritance.',
                'enterpriseca': f'As the owner, they can grant themselves CA management rights and issue trusted login certificates for any account in the domain.',
                'certtemplate': f'As the owner, they can reconfigure the template to issue login certificates for any account, including Domain Admins.',
                'domain': f'As the owner, they can rewrite the domain object\'s permissions and grant themselves domain-wide privileges such as DCSync.',
                '_': f'As the owner, they can grant themselves any permission on {dn}.',
            },
            'DCSync':                 {'_': 'Every password in the domain can be extracted, including all administrator accounts.'},
            'ForceChangePassword':    {'_': f'An attacker could reset {dn}\'s password, log in as them, and access everything that account can reach.'},
            'ChangePassword':         {'_': f'If the current password is known, an attacker could change it to maintain access.'},
            'ReadLAPSPassword':       {'_': f'An attacker could use this password to log in as a local administrator on {dn}.'},
            'ReadGMSAPassword':       {'_': f'An attacker could use this password to authenticate as {dn} on the network.'},
            'DumpSMSAPassword':       {'_': f'An attacker could use this password to authenticate as {dn} on the network.'},
            'AdminTo':                {'_': f'Users with local admin access to {dn} can access sensitive data, extract stored credentials, and use the machine to reach other systems on the network.'},
            'CanRDP':                 {'_': f'Unexpected users with Remote Desktop access to {dn} could access sensitive files, escalate privileges on the machine, or use it as a foothold to reach other systems.'},
            'CanPSRemote':            {'_': f'Unexpected users with remote command access to {dn} could run scripts, access sensitive data, escalate privileges, or move to other systems on the network.'},
            'ExecuteDCOM':            {'_': f'Unexpected users with remote execution access to {dn} could run commands, access sensitive data, or use it as a foothold to reach other systems.'},
            'CoerceAndRelayNTLMToADCS': {'_': f'The Certificate Authority issues a login certificate for {dn}. On a Domain Controller, this gives full control of the domain.'},
            'CoerceToTGT':            {'_': f'The captured credentials can be used to access other systems as {dn}.'},
            'GoldenCert':             {'_': 'Login certificates can be forged for any account in the domain, and this access survives password changes.'},
            'AddKeyCredential':       {'_': f'An attacker could log in as {dn} without needing the password.'},
            'AddKeyCredentialLink':   {'_': f'An attacker could log in as {dn} without needing the password.'},
            'AllowedToAct':           {'_': f'An attacker could log in to services on {dn} as any user, including administrators.'},
            'AllowedToDelegate':      {'_': f'An attacker could access services on {dn} as other users, including administrators.'},
            'AllExtendedRights': {
                'user': f'An attacker could reset {dn}\'s password or read sensitive stored credentials such as LAPS or gMSA passwords held on the account.',
                'computer': f'An attacker could read sensitive stored credentials on {dn} (such as the LAPS-managed local administrator password) or reset attributes used for authentication.',
                'domain': f'An attacker could replicate password data from the domain (DCSync), extracting every credential including the krbtgt hash needed to forge Kerberos tickets.',
                'certtemplate': f'An attacker could enrol against this template to obtain a certificate, which can then be used to log in as the account it issues for.',
                'enterpriseca': f'An attacker could exercise CA management rights to issue or approve certificates that authenticate as any account, including Domain Admins.',
                '_': f'An attacker could reset {dn}\'s password or read sensitive stored credentials.',
            },
            'HasSession': {
                'user': f'An attacker who already has administrator access to the computer can dump {dn}\'s credentials from memory and impersonate them across the network.',
                '_': f'An attacker who already has administrator access to the computer can dump the logged-in user\'s credentials and impersonate them.',
            },
            'AddAllowedToAct': {
                'computer': f'An attacker could register a controlled account as a delegate of {dn} and then use Kerberos to authenticate to it as any user, including administrators.',
                '_': f'An attacker could configure resource-based constrained delegation on {dn} and impersonate any user against it, including administrators.',
            },
            'CoerceAndRelayNTLMToSMB': {
                'computer': f'An attacker could coerce {dn} into authenticating, relay the credentials to an SMB service to gain admin or share access, and use that foothold to harvest further credentials.',
                '_': f'An attacker could coerce the target into authenticating and relay the credentials to obtain admin or share access on a downstream service.',
            },
            'CoerceAndRelayNTLMToLDAP': {
                'computer': f'An attacker could coerce {dn} into authenticating and relay the session to LDAP to modify directory objects as that account, enabling shadow-credential or delegation takeover routes.',
                '_': f'An attacker could coerce the target into authenticating and relay the session to LDAP to modify directory objects as the coerced account.',
            },
            'CoerceAndRelayNTLMToLDAPS': {
                'computer': f'An attacker could coerce {dn} into authenticating and relay the session to LDAPS to modify directory objects as that account, enabling shadow-credential or delegation takeover routes.',
                '_': f'An attacker could coerce the target into authenticating and relay the session to LDAPS to modify directory objects as the coerced account.',
            },
            'HasSIDHistory': {
                '_': f'An attacker controlling this account carries the access of {dn} as well, including any privileged group memberships from the original principal. This is a common persistence technique that survives password resets.',
            },
            'AbuseTGTDelegation': {
                '_': f'An attacker who controls a host with unconstrained delegation can coerce {dn} into authenticating, capture the Ticket Granting Ticket left in memory, and reuse it to impersonate {dn}, including against Domain Controllers if the captured account is privileged.',
            },
            'CrossForestTrust': {
                '_': f'A compromise of the trusted forest can extend across this trust to reach {dn}. Forest trusts widen the blast radius of any incident in either forest unless SID filtering and selective authentication are enforced.',
            },
            'LocalAdminRequired': {
                '_': f'Local administrator rights on {dn} allow credential dumping, persistence, and lateral movement. SCCM-managed administrative rights commonly span a large estate, so each entry is worth reviewing.',
            },
            'CoerceAndRelayToSMB': {
                'computer': f'An attacker could coerce {dn} into authenticating, relay the credentials to an SMB service to gain admin or share access, and use that foothold to harvest further credentials, particularly on SCCM-managed hosts.',
                '_': f'An attacker could coerce the target into authenticating and relay the credentials to obtain admin or share access on a downstream service.',
            },
            'CoerceAndRelayToMSSQL': {
                'computer': f'An attacker could coerce {dn} into authenticating and relay to a SQL Server, gaining the coerced account\'s SQL access. On SCCM databases this typically means full control of the SCCM site and every managed client.',
                '_': f'An attacker could coerce the target into authenticating and relay the credentials to a SQL Server, gaining administrative access to its databases.',
            },
            'CoerceAndRelayToAdminService': {
                'computer': f'An attacker could coerce {dn} into authenticating and relay to the SCCM AdminService API, gaining the coerced account\'s SCCM rights, which often equates to running arbitrary code on every managed client.',
                '_': f'An attacker could coerce the target into authenticating and relay the credentials to the SCCM AdminService, gaining administrative control over SCCM-managed clients.',
            },
            'CoerceAndRelayToADCS': {
                'computer': f'An attacker could coerce {dn} into authenticating and relay the credentials to the Certificate Authority to obtain a login certificate for the coerced account, which on a privileged account leads directly to full domain compromise.',
                '_': f'An attacker could coerce the target into authenticating and relay the credentials to the Certificate Authority to obtain a login certificate for the coerced account.',
            },
            'AddMember':              {'group': None, '_': f'An attacker could add accounts to {dn} and gain its access.'},
            'AddSelf':                {'group': None, '_': f'An attacker could join {dn} and gain its access.'},
            'MemberOf':               {'_': None},  # fall through to reason-based lookup below
            'Contains':               {'_': f'Every account and computer within {dn} can be accessed or modified.'},
            'GPLink':                 {'_': f'Scripts, software, and security settings pushed by this policy affect all linked systems.'},
            'WriteGPLink':            {'_': f'An attacker could link a policy to {dn} that runs malicious scripts or changes security settings on every system in scope.'},
            'WriteSPN':               {'_': f'An attacker could crack {dn}\'s password offline and log in as that account.'},
            'ManageCA':               {'_': 'Login certificates can be issued for any account in the domain, including Domain Admins.'},
            'ManageCertificates':     {'_': 'Certificate requests for privileged accounts can be approved.'},
            'SQLAdmin':               {'_': f'An attacker could access all databases on {dn} and potentially run operating system commands on the server.'},
            'SyncLAPSPassword':       {'_': f'An attacker could set {dn}\'s admin password to one they control, creating a permanent backdoor.'},
            'WriteAccountRestrictions': {'_': f'An attacker could weaken {dn}\'s security settings to enable further attacks.'},
        }

        if final_edge in edge_impact:
            m = edge_impact[final_edge]
            result = m.get(dt, m.get('_', ''))
            if result is not None:
                return result
            # None means fall through to reason-based lookup

        if final_edge and final_edge.startswith('ADCSESC'):
            return f'An attacker could exploit this to obtain a login certificate for any account, including Domain Admins.'

        if 'domain controller' in rl:
            return f'An attacker who reaches {dn} gains full control of every account and system in the domain.'
        if 'domain admin' in rl or 'privileged user' in rl:
            return f'{dn} has domain-level admin access, so compromising this account gives full control of the domain.'
        if 'dnsadmins' in rl:
            return f'DnsAdmins members can load code on Domain Controllers, which leads to full domain compromise.'
        if 'domain root' in rl:
            return f'This gives control over domain-wide settings and every resource.'
        if 'group policy' in rl:
            return f'An attacker could edit this policy to run malicious scripts or change security settings on every linked system.'
        if 'organizational unit' in rl or 'container' in rl:
            return f'An attacker could access or modify every account and computer within {dn}.'
        if 'certificate' in rl:
            return f'An attacker could issue login certificates for any account in the domain.'
        if 'privileged' in rl and dt == 'group':
            dn_upper = dn.upper().split('@')[0]
            group_impacts = {
                'DOMAIN ADMINS': f'Members of {dn} have full administrative control over every system and account in the domain.',
                'ENTERPRISE ADMINS': f'Members of {dn} have full administrative control over every domain in the Active Directory forest.',
                'ADMINISTRATORS': f'Members of {dn} have the highest level of access on the systems where this group applies.',
                'SCHEMA ADMINS': f'Members of {dn} can modify the Active Directory schema, which defines the structure of every object in the directory.',
                'DOMAIN CONTROLLERS': f'Members of {dn} have access equivalent to a Domain Controller, including the ability to replicate all domain data.',
                'ACCOUNT OPERATORS': f'Members of {dn} can create and modify most user and group accounts in the domain, which can be used to grant themselves further access.',
                'SERVER OPERATORS': f'Members of {dn} can log in to Domain Controllers, manage services, and access shared resources on those servers.',
                'BACKUP OPERATORS': f'Members of {dn} can back up and restore any file on any system, including reading the Active Directory database which contains all password hashes.',
                'PRINT OPERATORS': f'Members of {dn} can load device drivers on Domain Controllers, which can be used to run code with system-level access.',
                'DNSADMINS': f'Members of {dn} can configure the DNS service on Domain Controllers to load external code, which can be used to gain full domain control.',
                'CERT PUBLISHERS': f'Members of {dn} can publish certificates to the directory, which could be abused to interfere with certificate-based authentication.',
                'GROUP POLICY CREATOR OWNERS': f'Members of {dn} can create new Group Policies in the domain, which can be linked to push scripts or security changes to systems.',
                'CRYPTOGRAPHIC OPERATORS': f'Members of {dn} can configure cryptographic operations on the system, which could be used to weaken security controls.',
                'HYPER-V ADMINISTRATORS': f'Members of {dn} have full control over virtual machines on the host, including the ability to access the virtual disks of Domain Controllers.',
                'REMOTE DESKTOP USERS': f'Members of {dn} can log in remotely via Remote Desktop, which could expose sensitive data or provide a foothold for further attacks.',
                'REMOTE MANAGEMENT USERS': f'Members of {dn} can run commands remotely on systems, which could be used to access sensitive data or move to other machines.',
                'DISTRIBUTED COM USERS': f'Members of {dn} can execute remote applications on servers, which could be used to run commands and access sensitive data.',
                'PERFORMANCE LOG USERS': f'Members of {dn} can collect system performance data, which may expose sensitive process information or be used to escalate privileges.',
                'PERFORMANCE MONITOR USERS': f'Members of {dn} can monitor system performance data, which may expose sensitive process and service information.',
                'ACCESS CONTROL ASSISTANCE OPERATORS': f'Members of {dn} can query authorisation attributes and permissions on resources, which could help map out further attack paths.',
                'INCOMING FOREST TRUST BUILDERS': f'Members of {dn} can create inbound forest trusts, which could allow users from an attacker-controlled forest to access this domain.',
                'KEY ADMINS': f'Members of {dn} can manage key credential objects in the domain, which could be used to configure alternative login methods for any account.',
                'ENTERPRISE KEY ADMINS': f'Members of {dn} can manage key credential objects across the forest, which could be used to configure alternative login methods for any account.',
                'CERTIFICATE ADMINS': f'Members of {dn} can manage the Certificate Authority, including issuing certificates that allow login as any account.',
                'EXCHANGE ORGANIZATION ADMINISTRATORS': f'Members of {dn} have full control over Exchange, which historically includes permissions that can be used to escalate to Domain Admin.',
                'EXCHANGE TRUSTED SUBSYSTEM': f'Members of {dn} have write access to Active Directory objects used by Exchange, which can be abused to modify permissions on domain objects.',
                'PROTECTED USERS': f'Members of {dn} have additional credential protections applied, but membership itself indicates these are high-value accounts worth targeting.',
            }
            for group_key, impact in sorted(group_impacts.items(),
                                                key=lambda kv: len(kv[0]),
                                                reverse=True):
                if group_key in dn_upper:
                    return impact
            return f'Members of {dn} have elevated access that unexpected users should not have. Review whether this membership is required.'

        return f'An attacker could use this access to reach more sensitive systems and accounts.'

    def _find_representative(self, path_group, category):
        for entity_name in path_group.get('entities', []):
            entity = self._entity_lookup.get((entity_name or '').lower(), {})
            for risk in entity.get('risks') or []:
                if not isinstance(risk, dict) or risk.get('category') != category:
                    continue
                details = risk.get('details') or {}
                if details.get('shortest_path_names') and details.get('path_object_details'):
                    return details
        return None

    @staticmethod
    def _get_high_value_reason(name, obj_type, labels, dn):
        dn_upper = (dn or '').upper()

        if obj_type == 'Domain':
            return 'Domain root object'
        if obj_type == 'CertTemplate' or 'CertTemplate' in labels:
            return 'Certificate Template'
        if obj_type == 'EnterpriseCA' or 'EnterpriseCA' in labels:
            return 'Enterprise Certificate Authority'
        if obj_type == 'AIACA' or 'AIACA' in labels:
            return 'Authority Information Access CA'
        if obj_type == 'RootCA' or 'RootCA' in labels:
            return 'Root Certificate Authority'
        if obj_type == 'NTAuthStore' or 'NTAuthStore' in labels:
            return 'NTAuth Certificate Store'
        if obj_type == 'IssuancePolicy' or 'IssuancePolicy' in labels:
            return 'Certificate Issuance Policy'
        if obj_type == 'Computer' and 'DOMAIN CONTROLLERS' in dn_upper:
            return 'Domain Controller'
        if obj_type == 'GPO':
            return 'Group Policy Object'
        if obj_type == 'OU':
            return 'Organizational Unit'
        if obj_type == 'Container':
            return 'AD Container'

        # for groups/users/computers fall back to the BH Tier Zero tag
        if 'Tag_Tier_Zero' in labels:
            if obj_type == 'Group':
                return 'Privileged group'
            if obj_type == 'User':
                return 'Privileged user'
            if obj_type == 'Computer':
                return 'High-value server'
            return 'High-value asset'

        return ''


    def _get_categories(self):
        cats = []
        for cat_name, (sev_key, _cls, _lbl, _src, _dname) in _CATEGORIES.items():
            sev_data = self.domain_summary.get(sev_key, {})
            if isinstance(sev_data, dict) and cat_name in sev_data:
                cats.append((cat_name, sev_key, sev_data[cat_name]))
        return cats


    def _build_html(self):
        categories = self._get_categories()

        # one pass over entities, reused across every card below
        self._entity_lookup = self._build_entity_lookup()
        self._entity_groups, self._dest_cache = self._build_path_caches()
        client_entities, group_sets = self._build_client_entity_data()
        self._client_report_data = {
            'entities': client_entities,
            'groupSets': group_sets,
            'pathGroups': {},
            'highValueGroups': sorted(HIGH_VALUE_GROUPS_UPPER),
        }

        # totals are post-suppressed-edge-filter, unique entities
        total_users = 0
        total_computers = 0
        self._visible_path_groups = {}
        for cat_name, _sev, cat_data in categories:
            pgs = cat_data.get('path_groups', [])
            unique_ents = set()
            visible_groups = []
            for pg in pgs:
                steps = self._get_path_steps(pg.get('path_string', ''))
                if not any(s['edge'] in _SUPPRESSED_EDGES for s in steps):
                    unique_ents.update(pg.get('entities', []))
                    visible_groups.append((pg, steps))
            visible_groups.sort(key=lambda item: item[0].get('count', 0), reverse=True)
            self._visible_path_groups[cat_name] = visible_groups
            if 'Users' in cat_name:
                total_users = len(unique_ents)
            else:
                total_computers = len(unique_ents)

        parts = []
        parts.append('<!DOCTYPE html>\n<html lang="en">\n<head>')
        parts.append('<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">')
        parts.append(f'<title>Attack Path Analysis &ndash; {_h(self.domain)}</title>')
        parts.append(f'<style>{CSS}</style>')
        parts.append('</head>\n<body>\n<div class="container">')

        parts.append('<div id="logo-container"><img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAKEAAAAjCAYAAAD8KWplAAAAAXNSR0IArs4c6QAAAIRlWElmTU0AKgAAAAgABQESAAMAAAABAAEAAAEaAAUAAAABAAAASgEbAAUAAAABAAAAUgEoAAMAAAABAAIAAIdpAAQAAAABAAAAWgAAAAAAAAAGAAAAAQAAAAYAAAABAAOgAQADAAAAAQABAACgAgAEAAAAAQAAAKGgAwAEAAAAAQAAACMAAAAAGllmhgAAAAlwSFlzAAAA7AAAAOwBeShxvQAAAVlpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IlhNUCBDb3JlIDYuMC4wIj4KICAgPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4KICAgICAgPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIKICAgICAgICAgICAgeG1sbnM6dGlmZj0iaHR0cDovL25zLmFkb2JlLmNvbS90aWZmLzEuMC8iPgogICAgICAgICA8dGlmZjpPcmllbnRhdGlvbj4xPC90aWZmOk9yaWVudGF0aW9uPgogICAgICA8L3JkZjpEZXNjcmlwdGlvbj4KICAgPC9yZGY6UkRGPgo8L3g6eG1wbWV0YT4KGV7hBwAAHRFJREFUeAHtnAmYXUWVx0/dd9/SWxLSS0K+DGZIgCTN9hGWkRkkOgojKq5xnBEdZ5A1DIIgjrgQXEAZQYcQoigqiuBnEGQWVFRoGHABe9BAJyyRr2VJSLoTsnX32+6t+Z269/Z7/fq97iYk841+1Nf33XtrOVV16l+nzjlVt83wctkteytYCJkpEovzWutKlHxPppdD+WHL9fJ2u0xSZo0EU6T0SrY/cg4w9tKy1/owVQBqhUle7oGVMJMRKY9I015ryyuE/mg44AehqEwaGxKAjI2N3sbnjuK1TL20RrSSvKQbI2UJJQMwX5F+9Xg+Nq4Rp8fm+iN68xn4ejAJ6UMjQDQqU5FuMQPAWQjx+nSM+GSL6o6WZC1Vry0xtTG3lMgShHht6C0Tk8C7NjF5p44lWndV6NU2ap//H4Zl9PVp+tpGv3q0b3rRh6XE7eLeO9FYaX8a8EqTGoWJaC6Fd1rvZKG3FOWozq98XkbZNZqkPOd5iW+Gzh07aOhoNgvM/HREova3WGTZDChTH7zV2cMmXzxTM9wuA2zMQyekLt61Q+XmjPjDRfkROuEpk+iEml/LNQoTpe9pWqO69mG8Dl6PDtREfU3qB2jLeF6j+avDRP2tzlfvmbJLodujE3sfBJ1cUXtrIRLmAE4+kCeKodwOIJup3UkIJ3ZYNok7LZ2S/Uuhi68jjRyqgmxKUiNl+bWU5OfWSIunS20k8ULeM8bKB1JG2tAHp8LkhAlaX5hrX/R61vATQmuHxPOIg2Jog6KfXiWb1w6Rpx7zXdm2OQd3FEr+GY4gZWhXqzHe3SMDfQ8Q5/K4tL33Q1vGSd6JJLa2nXZEg9/Uvvg4lpMT4Pti1JZZpKE9S5H3F4yxj9qU/Xlx8+OPRtLFATcBjetLrr37dWLsiRVeTdAxxtTz7EAg5pHSQN9vozZUTYYFC7LZHZmzGLI2cpZppba1EhQpnvWMNflCbtpqee6XI9n27uXWs9M9a3Mk3hvacAYjtjU/sOZ+mXHkjEyqdFYtCIOUSq9Aft2ySi6tUK88DZ0jx8cgbAgeIBF4GZaBvPw7ku2KSunKExL4bVhFbQHQpCcNaVVK6NMSZk+vgvjdJpU9wwuR+IyMK+2nJBcUm/Iil0eDniwHCYWlOrBhoZyZ4xkTtcmjWi8tYVDMkgsQRvSTEnvhroNEJbVtcZTjtDG1JHFBpqv7nUzUTzGuhzNJotEGeUkwzB4XUOqzHYvvsZ53YXFLz1qRBIgJr+wyk8qc7YVgU3k1UYC72loP+ZLrWPQbni7JD/bcC19YF+nDYGuT+MWrPS8NSshYS07LE2mRN62loZtxu4xA7Cdku5L4dfnBvvtp64/pRjsZj8r5hXfB/8/XgtCR5QfUijx7oTTNnY4s2wiFF8V0r5EidbiqNL1hUIlHG20orZpn45nSvP8cymr/LpPStvOljXbqTN3DYHYKALQ2HKaeyKAJAr1/rGnm4TeObOt9DsJOElQq6KRFhLItWzci7q1owlIz/d17bipH1v0oL21LZ/dscHIS4686krHWepmSuWvnzr5t+q55uMaEbOfilUa88zSJPqK1BMo7fVUpGPXLmgLU9DltTOp1MPt3mc7F7y4O9KBwKRATumaXAEBrgxGmezTe9QxAC+TJRTnNg0KWOpr7PbmO7rPyg7038EzNu5kTmU02DOaQt0ANNUqbAemWBU62m1TeraCFgb4NtOsRlqoHoYC6YB4hzyFNXYceT9/m27B8T30gUELrVACaFVI2N0jJAVAjaUXoUpNORpH1fpnATkfZXyI6CkAGw8703YDUKzLFOJOKZ7UywaclKsnKDEbWpoLPRUSW1u+bE7wxoxnAiI6dfGJNsWWVbKpPaaPkCEn5N1ljbrHG+y7P3yml7UFRvihP/OyAw4Bdaox/HgPNkuvEF4Lfy+kFZAGy3UH+0Hge7ixDvxXXATNSEW2+39TefaxbRuf1R4ADFFEfjfLKXQm9MXfjNRkv1UxeBbqCv8QFUfPVXMfCEzWurQlLwUgX+VJIZ1XVtI6ELsA1SiNDU7pskBvlvyd2GsvXfkoDym1A/RtMrRt5eRI8PDOa0aUnPxVr1bMrELw4j7nHnZJntfsEncWJ/uEixv0kdOa4vLpQahkZKExBmo4jNmmEz8AhNeT9qke5gYgkwkQFyT7loLwCWKpQ6+UkkutPfQqRBWkCJK9FEkmYV7AorsrGiw0Il0fpcvWUVWpC8JMOe9EAozmYFCi7j/KneGVzcNovHWT88CAJgveBlGc0PWqXLaqtiEBb6drT3x7XMdq6pK+MWXi6DYKToHsqbXsL7XpzGAZvkzC8DEhvA0xxXxNh4V2lVHY9n9plQ/sehPNbqPsy8mn/VSSFFKHy8BponYJq8M7dHcF24rVt4M6MkFxwz0yKlPV7qfsXJvB/ikCzCbBcOhSjhsbi2qxwS2hUFiGvgFzXJ++eJ/KpjCcfRw2T4TJ5IrFcb0AikPZFEjEiJNI5ICPDnXFdSeTLu2u79UKHNx4/X+B5KQMbyWxe9jwo4AboW2IlOvdCQo54py9pP5NBjtOcu4ip6gXKGKQKEiOR4GEMkERXXMo49GjkyWAq5yQbBR0Axf60MNh3UlJhfB/g3j9tWvddhUz4O57nKv4AKgNtjm1u7z5meGvvw3HemnaJTWfCO3c9//jWOL36dmduxqKbTNo8jOTWEQIrzGtjjk13LFxSGuzrLW6VH2qBdMehL8CYyyHOn7LZ9fKewsD6HzmCW9yvRmIaBNfIdFQKWl0oZy+R7TNQf3pOdzmmdV88BoRQoyvKMGmx6HHDGZmB/pkuFJipadb5FfIiBVU/+QQGyh2FUL7RkpPDh7AGqE0HokIvojPdfkBy29pERfzONX1idpwuM3dAN22RrkTupQD2dKF3OpQuyyeyrC0rDqwDMbFS/dIroku6XK6JJlLHIW2ZwHtVKu1Nx0VV9G1q08i2tc9VjI6Ky8FV1XFIqww+scuaAJ0TMiybSRN8Y5pZV0VmLpgm08pF6R+IJ4s9OM4zmhcpcq2LmzcvJ/39Kk3caMusw5t3bl67Df3xKuNlrkXvU5UE2ePzWDqVpwSELrrqxxSLKV0atwrWrmyYW5GYs7Zl85vX/gGan4WH/8Zk0HaBR0931l7Nc690drfKQN/ulA2nM09isnq3gMSb5iKitoIKRRPthQ8y6FKMbP+tSsgkGEE3roAmilZfnYY3DfuyCYC30Ion0xkJm33pHj5Xrmvqkg8BxrBlNQ0SOQIr9zLfyAp8i76TiqHqWZIe0Tlp5Mxiq1zQXJb3kveWv9pPsr4v9/G8iMsWo+6rnRUPArEvLegs1a6qnvQMz4cBROf1YcivIO4HMUh04F5KiAYa6dfUtfD40HoXQu81aFddut6rUwjvzgiW3np6eXNhcDFAUZ9XN5OtrygANmv8B0zH4tluUkfdUyTSViaKmDsoO0LTm2V39g/5mYXXyTZ1uxjw6XLF7dV5ZXUCM/XbqbU/bhckNq8d1uiUDX4QBEU1ysC1CW25pO6whzStUTAe00jDhg2U2VDh/WZtrfbNPqAWMkHbHOW19s81QlqGyirRVMK799Eflk8TS/j+eUzc/iQlAmL0ps+KWCWe9EXZWTd4OI8V1Y/vKMvRzV1y9FBJrmlqkfOGt8gLI+fICUkpXDCXc/DgiOGS9DZnkXiqmFR0xWxG56fKUcL+XCS2Nacj0aBxLys4ua00bYhv6nxGDB8hCrgNiyjIC7Idiy6K6KufDqE4tZAwB9fHInQc/0Ek2bvgXhfF0WB4Ahn8ZJEQR1HPNdmOvvWZ9sMWOgBqHWEAluwcREhXXE5jla4LFO/k4QAY0wGdOdr8KCHsd/fRH6SLsZdKN+De2Kug08GDpC7fKqWXpYYHn9hYGFx3dWFg3bVYotcVt/Z9AVfIvdGEcIRG6x0lW3moTYO2DpfdTR+1rmp8qCGyp0HpOtrcla6G0ffqSqKk6Bd/pXt4YM4NMiwrpNC6Wi4azstRFN2Zmyb3IwFXs2Q7cJG2FjAePTQil2oxQOZTg6445XgeuYo3EcHwlQHt3gtOssiMfMp7GOft5wGFQyXKM3WYT7bOXsCAq+5Vb5uvbjNcz7Md3V8zXvpCBCuSNcirrs4Fv+yIEma5wv+K1LVlTTvImODh3KzDDlSK08pZ7T9OcDVMHYsThmuyLm9RPHcS2iSVjjiSSt2NcaV5ARkuXuiTcUl2s32KCXFBBHQlofqpXip9AeScJQBEpbCCU9UPneSdU+FydbsottQ1Fn/zfnHDq2jg6tlHwVVaS7tqekR28JnKFCTxSnmEZXjB7p3y6eZmOXvIl4Hdy+Wvk/KA8Uq4ship+MvmnAOouk/gZ0UK8BQNS1LoZd9da8tNJdkvP7D+syhEYB3XhbF5ANlWKmc+7aqYt5WBmSTMzWg/2ZFZfBp4+yBWKsoJMhb3CIC4j5XpRC9MHWJtCnUiuJK8KfqmaVh/qVYs1m9pDTu7CkOsaR8Gv+cB4FUMqDYyGVAMULUiw3PwglwCOy6Uwf0V2F5hy2O/p74vooLpekLd2LoREA8g7ksAfT3L+GPZzu5VmfZFb1dr2oHRSUnUABecscMwNA429Nx4ohMCWAVtfM3d4IQKHT4lnjxKxzGYnw2NKb68lKgxDWhEQobEFyUcukD2b/kyeiKhbbVcVlgu3+fxtpY2+dnQcvlm85Cca74l+bbrBT1Jjkd/vIiGfw63dwq7KBmAKjQqpb0U8GuGqcA52Bm3fwFANyFRkCSOh2dnug5dXex/jN2EScJzWZXeirrLWCKV/QpAXwGIhbq0pvSlKPCbSL8WQKWpD4PIO0G3FPMb1v8MlXi15k9jqaY8sxxNUHmgIpBb+BWsyKc0vSq4waaeS3Idi+cAuvfqzgNLh1tRVOiSN0cd3dDoxnY+t2zDIUD5EIi9NT9LbpK+HoCo0lClZMNgC0U/MhM2bKCZVeE5KUU6sHwUlUITdOIa+qatf9Dl9FXI791QVxImVTiu8KIHTG1Rrt59jtyqPkNNz66SvtbrZdHwDvk4Uu8fh5tlKxbzG5OyzdfL1VjPC4d2SR90nD6hOuFe74FWqOZJKXCMz2/t+7bY8i8YLJYn/FO69IXhF5J2TXzvKbPX+lrKLGDw1bmXBYAUKZ9Vrxx62EoAuI78OGpRPVQTNN47XF61IgleKnHSVijgQ5rp3tSKdKBxb1qRG4/84LrTAMGZiMGNLOlpdNIsfdFJhl3k/I34HHXPUlqo+7VYSjewZP8+27HwzREAnR/TER3/Y7xsuvxBgP7eXOfif8p1dn/AXR2LPgigv8psvp+6qM8NlU4shs/2FLfhnNP2VVvT44nvUcyEIKwGDE0pt8yQ9+DfezK/XN6Q1MbyfEUhL4cwCE81T5e7OKn9XXtxdFB2v69If8uAHIF9d6fLP4eBoodJ2b17r7hA2Pu+SG1QmAeInIT6G3Q8dVvgGW10ridujbEnOGmlvlKVWsY+jc1awH/2qtzshfPcneds16Hz8dMpmFimXJdAoOod9ihHaSDnpIwJYosxJq+3smHHXEP/MQBpjNRSaanEPIyLr+Vbh+cjhlQi3kZ3nqc9+A5T0e6JGmDo3QpGJFWJtLnosP+hwHK64uiOCbnGBLbVjH8Vs+Nm3JY3ohx9012ejw6cOhMOqYqh7aNtht0PYC8SG3j7ZuwmBOGYtit7sM/YGDwQd8zdGCY3qC9R8+RWyZMceDhyaKdc3JSRvx8ZkW0s0W/VNJWiLfs5o149U24x0vh9FvB9jWxb/ytW6JtgKv0zKjEI1klDw95x9D7mt2pimPkuRd1eKgWtHGDL3mOAdx33PnfnGQVgbSFjn2FYTlagk0/1N266Oe98kxHQxlSTvDjVK3mpvevsgdvQ6O/Pjwz23YLEXcaplIM4WYK7KPg4wPs5DdtF/5SQXgDHKhi1yTciEQ/WsjFhpTcmgLE8+u4Ixtu4i4zwS4GaUk8H/bF/Wxpc/z+xxJ6gT2OqeEkvdUGYtFpXlzHUyM16kMfwCFiCz8CX+BRL8JuSPCzPV+/Iy3wY8bvmafJD0m4DqNPNikgnNCtFpUM9ECQkXv59w3SdLnrI42MMiro1mnQngRVzoS476ZSZcCrA9GlxrxWYutD7DHYLV3Odi+UwhasmhX/Py5CuVc+WOQ4YY3mnKZMG1eeSSw+xJkYDyyvHoka2PP5LHPBX4JJ5fSZTPhAQfRigwFNn66l+r64pbqlzJqqK5T0HP9jn1f3imgtxqjSZWHfhODqS+tD9J9UzJ6pu0jRteL2Avs0IsKuRJDKy+Bt0VETLpIYLUuTM4JxUSv4TqXdT3pPz21fKzhmr5WnSj8UwOQ+/4Uqc3+8cWc5+7ir5Dkv1cdCcX9bhUUlTJX+Sel7+XU/vLkkPD/ZuyrR3fwZheCUMpS9EW3s5G+eP43xT6VhXHNGk2Mp0ANR5OEjZHt50g348sHAkRiBQwyPMkOUF2ZhP1I7x+Sfs4JiluSpnr3KKaxmjoqese8NdG59U4+JLqBm/J+VO2qd1OelNm4+pKlzDZRSEsHwpzN/ITFVd001aRz9knfBkixf4j0W7QUpl3wJQaxgHQm0xQCmXCoIE4DxYHBiNkVI0PCqS1fWSKQToDowvUvEf2CB8486z5expX5E7tAiGyXUAUXXB76U9+TbL97nQncd7gJ9QJVQL1z4K0b4tjturULZPR1BgaKDIG3NA6Ll9ZZYq1anGY4Q2bop9SOz5mjRL7PNInmUvvaFu8JIBrikeawg1sWw1fow65zIAeYCVMaHZnp8tn5E+535haNxJ5HhJjOhjTf8XVno/fZsXzTR6ZUwbpAFrxStRqQpPftn/mux4VLdgJwoIIO12vG05Uc6XmVYLwjI6nW7d/XhbTk5rHonOFWod7KBcvKskH6VlP8EZvUSXZKKdpGSLrsiBhi4/I7cDvFtZ/5ab1fIiQHyWPH+5+0Myyy+zBcjWUpOR4byRafiSH8xwQputO90uGI8GrXTPA/ScXobibi/BqLqdCAQE0sqY1+gsi6ukahdG6wcE6D8EJLVTycUeqkaI8+G5vdYNkTqxYIHPtldBDwuA1tniBQUJ/Qx+oS0jW/seqnyHMV56+tb3IhiuU/5p3doOfErmHTiuj9bzf7QT7hrJbSnfzYz5b5n76hxLciKl8U0PeNKHajN3bpPJ2xaAB4mIj+jDej6ywQTA9M2UO1jDX4z2jiP1RQtHwX3LomUZ3zq7TGrw9FOvDVkZFedJ0MMA7kSPSJInSZrkPgaEdEPNO+3/8OwvyhBl9dKeGfNlcRvPgKzCiJg4Y5opou3y/YllCf47QHzyrnPkbPyJa+wKFr8VsjnO6m64ebZjZbvTJdXxe/fZOW1Txa3r78C5+1P0tjewrOpJWK2mmnv67kYweij9LLS+6q7qpiihO+EDDM/i+RJx+iY7Lwt24KrYUGjpOnRWOQxxB6U4RgYRdJMwLK0k70OizvF+p+QrR4mqhMDngKkLiYM5MmTQt2/jvO3RzBVdKQAorhIr14K441QnrFDgqa/PScRMYdoFgIETL84pShHmWmjWVuUdnWBJHOeMoonk9o4bgjXJPvYeGzzsE29PjbJRMcvBCQl2uswVo2hs2QZvYwZDwebyxbpgsi2ncQomdx8/gK4IPzqrfXTFEg8zW1vl+xgmy9UooawedDSJj1Fe5STs2JFJqOzVe7SKWi+4SIWgto+rcb1IlZGtTz5P1lucgo+bRi1OSnwkcn0osLnUycsJGJSrH2CQ4L1FCjL0elyQu4KQmmKnbu1GvzIi8F+l37qohOUk+FyRA13jkCS30E4FSDPgYw+ciWq8I7Mddl2uc9HpmVkLD1MXkVq/2a7ukzmCfyuS+4qob+6UtdMJPc/c7Now+U9jXowtG+dbktbTSfrpAZ8QvTVSQ/HnO7GtXTcnsZPztkxH93uclI1oTFrHGEmY1Os4oi9srSdxsqLqeTRy/AM1pvHt5xHYePd1k56wUXcemKvd0FAJzxLs4vf5j+pQS9LFzb2Pojddh8TSE8sAqb5RIrmca1e2GH6klJNTsc7aYTTH4m0T0uZGrOvTgdpv8NbNIO7NxM0EAPrJAz5qTjsFwedwND8lqsxv6NF6UPu9DXwTpMBSyUZ79BS3vb1YTBMXNoWpsF/mPN0Nj0ZGtj32LHvEl2KgXgUWNa+6fdQJPh8x+3V1L2IGsRJhsVMjN7K441aoGQpYP0v/vp4f6HswWmrdjsikINB2ThKUhpUZQQsP33HOc7Vn9KxhLJTgAwqMd75nvPN1HrXszM1mGdUVMCo7QQVjJGFVPtfw53ZI2q5AerB3jGoeWZNuwa7KWfMYozaxpN1AbGLQHR3kA6uh2VZuAIIaWo1fkVW6rGJAKSfI5+qpn999UyyFYupT7EKoMu5cENwVGPHyHFuIbjdgqb9r1+Nb8VS/Hsbii3PnyOFwWKDG45GQ58PX9/M8U+MACBaxn0OPu5ndmk9EbegBQDrRlqViK/MbAAueOl2AtqoyBZxUj6t4ICC5LFUYXP+vAIkzguyUgGzoKNIK6tNz7XXvyc6Ji2Nnms1mXEX073sYKme4NsSuKupyzsO4LH3GM1DPyneFJvnRb0ysbKF9HNxwKkPEw4j/PLObw2FGGjRgvOgbEyjSr4mDdrI6uAKwxjk6/+xLFes4yQTfxumESdroHcng8I9uqXHuJE6SuMI97MRadlIniX5pdz45VHdWWGqJxjNskWzDY2nUg861o/dF277oE8bPrEJxyzrlQt0r0OFj0dhS1+P2uuQu9UsDPb9t7jhkIXJmNQN3KgONfqbsiXjqlmv3bUuAC6f8aSzoaBmOJEPctzXuTtrZbJPp9xunQSfqKqcgtO2UnSlBiXo1rFHiBiB9NNu56D6k3Qrej3EA0xxR1TzQev3nAcQBBqLDx5hGn0cKf1cTCVSiBoaGhFdlrV8LoL/qmfg9CGEr51aL+9N3dY5DbxwNBkXtv6DThqPfmIxt+bgi0ayqjk7pDiytP273ufqZnvvfMHg1ogBHdRd9fknnOcyKYuv84lNjkVJCp6IX4tB1h2OVW7oTGbA263fHM+IjXY3pjCMdSTWWg1vCsNBPdzmtEjIYtlwo5bfG2StDNVreGSlS2Drrhmz7AC2HgRx5ZuYyhmFzygvvjbJG9KOttKX+8GDPRuLfqrqYLYdvZM/sMIjPJE4l7zMs1Q8WbXiXOzkcgU/rjgHIk2Olg3sIQN6X7uy+2guDv6AB7DTp1xUB4tHbIZtnqiGkQcvCj6V+YaDnLp7v4vDF4Ui4VxO9EKt3FqtwFt6hfFrtyBN8QPQrjt3/RgsTdKjiNvToO8TC74Vh8dmIV+rJhnPlgvoYNVS3NYqp/6s0RTp2j8j2zD8j7VqhjIQdhwHyoZsaUxjys7tiUlHZ+KXebdx/YCBTiLvFw91SN7j/wKBw0v5NHNyH9PGhobE5Kb2P/gODtqlRpydK0/bVS9dB1fho2mmuugEdcOwecG0upaG0JqFTXczR1PyN+lOdmee6bajXp6TcRGlJnv+Te+1yrJV6/PeFsMjXKQ1aoGW0A5MFj32DEM1rHJ2491OlU1uPDgozuvaQ6qT/h0bLUXXtf0NQ8k4C1pMKSVxcny5x+v2yfvikS3fiU+tR3WiioHXDBz3dojse1cHRqFPe0VRWVfVV8ybBfanHi1rWuuzXbYPmryqflJ2UV0nGOncFe1J3nWQX1ahP9fMrEKo6NppJO69pmug0idGU6KFemZos7nWUTnViVeHk0d2dylWdsfEzA5osnY0z1UmhnmhprpM2UdSe1ldDs3rHoyap/qvyZZK6e+uXrMROUr6ScWpPdcE+taINcvnoaAqUycJU8kxGo266EkbRdH5PnmukRN0ir0T+iXHAx/fgLNiX0i9nAMVK6VSea2lXl4nTSuiafEI43hqvLfvK+58eB/4XYdYmlan2ChgAAAAASUVORK5CYII=" alt="Logo"></div>')
        parts.append('<div class="report-header">')
        parts.append(f'<h1>Attack Path Analysis &ndash; {_h(self.domain)}</h1>')
        render_display = datetime.now().strftime('%-d %B %Y')
        parts.append(f'<p class="meta">Report generated: {_h(render_display)}</p>')
        parts.append('</div>')

        has_users = total_users > 0
        has_computers = total_computers > 0
        has_any = has_users or has_computers

        if has_users and has_computers:
            subject_phrase = 'a standard user or computer account'
        elif has_users:
            subject_phrase = 'a standard user account'
        else:
            subject_phrase = 'a computer account'

        parts.append('<div style="background:var(--white);border:1px solid var(--platinum);border-radius:6px;'
                     'padding:14px 18px;margin-bottom:20px;font-size:0.88rem;line-height:1.6;color:var(--primary-navy)">')
        if has_any:
            parts.append(f'<p style="margin:0 0 8px">This report identifies privilege escalation paths discovered in the '
                         f'<strong>{_h(self.domain)}</strong> Active Directory environment. Each path shows how {subject_phrase} '
                         f'could escalate privileges to reach a high-value target such as a '
                         f'Domain Controller, Domain Admin account, or Certificate Authority.</p>')
            parts.append('<p style="margin:0 0 8px">Some of the relationships identified may be intentional and required for '
                         'normal operations. For example, a helpdesk team may legitimately need password reset rights on user '
                         'accounts, or a service account may require delegation permissions to function correctly. '
                         'These should be reviewed against your organization\'s access requirements to confirm they are appropriate.</p>')
            parts.append('<p style="margin:0">However, every path listed in this report represents a potential route to '
                         'privilege escalation. Even where individual permissions are expected, the combination of relationships '
                         'in a path may create unintended risk. Each finding should be carefully reviewed and, where the path '
                         'is not operationally required, the unnecessary permissions should be removed.</p>')
        else:
            parts.append(f'<p style="margin:0 0 8px">No privilege escalation paths were identified in the '
                         f'<strong>{_h(self.domain)}</strong> Active Directory environment during this audit. '
                         f'Standard user and computer accounts do not appear to have routes to privileged targets '
                         f'such as Domain Controllers, Domain Admins, or Certificate Authorities.</p>')
            parts.append('<p style="margin:0">This does not mean the environment is entirely risk-free. '
                         'Access controls drift over time as accounts, groups, and delegations change, '
                         "so continue to monitor for configuration drift and re-audit periodically. "
                         'A clean result today reflects the state captured by the BloodHound collection that produced this report.</p>')
        parts.append('</div>')

        if has_any:
            parts.append('<div class="stat-row">')
            if has_users:
                parts.append(f'<div class="stat-card">'
                             f'<div class="stat-number">{total_users:,}</div>'
                             f'<div class="stat-label">user{"s" if total_users != 1 else ""} with escalation paths</div>'
                             f'</div>')
            if has_computers:
                parts.append(f'<div class="stat-card">'
                             f'<div class="stat-number">{total_computers:,}</div>'
                             f'<div class="stat-label">computer{"s" if total_computers != 1 else ""} with escalation paths</div>'
                             f'</div>')
            parts.append('</div>')

            parts.append('<div class="tab-bar">')
            for i, (cat_name, _sev, cat_data) in enumerate(categories):
                tab_id = f'tab-{i}'
                active = ' active' if i == 0 else ''
                cat_entry = _CATEGORIES.get(cat_name)
                short_label = 'Users' if cat_entry and 'Users' in cat_name else 'Computers'
                tab_count = total_users if 'Users' in cat_name else total_computers
                parts.append(f'<button class="tab-btn{active}" data-tab="{tab_id}">{short_label} ({tab_count:,})</button>')
            parts.append('</div>')
            parts.append('<p class="tab-hint">Hover any node or arrow for details.</p>')

            for i, (cat_name, sev, cat_data) in enumerate(categories):
                tab_id = f'tab-{i}'
                active = ' active' if i == 0 else ''
                parts.append(f'<div id="{tab_id}" class="tab-pane{active}">')
                parts.append(self._build_category_section(cat_name, sev, cat_data))
                parts.append('</div>')

        parts.append('</div>')  # container
        parts.append('<div class="conf-footer">CONFIDENTIAL</div>')
        parts.append(f'<script type="application/json" id="report-data">{self._json_script_content(self._client_report_data)}</script>')
        # Release raw data after all cards and embedded report data have been built.
        self.entities = None
        self.data = None
        parts.append(f'<script>{JS}</script>')
        parts.append('</body>\n</html>')
        return '\n'.join(parts)

    def _build_category_section(self, cat_name, sev, cat_data):
        sev_cls, sev_lbl = _severity(cat_name)
        total = cat_data.get('total_count', 0)
        cat_entry = _CATEGORIES.get(cat_name)
        display_name = cat_entry[4] if cat_entry else cat_name

        visible = self._visible_path_groups.get(cat_name, [])
        affected_type = 'users' if 'Users' in cat_name else 'computers'

        sidebar_rows = []
        content_cards = []
        for pg, steps in visible:
            path_string = pg.get('path_string', '')
            count = pg.get('count', 0)
            card_id = self._path_card_id(cat_name, path_string)
            step_count = sum(1 for s in steps if s.get('edge'))
            last_node = steps[-1]['node'] if steps else ''
            dest_label = _h(last_node)
            filter_key = _h(last_node.lower())
            count_label = f'{count:,} affected {affected_type}' if count != 1 else f'affects 1 {affected_type[:-1]}'
            sidebar_rows.append(
                f'<li class="sidebar-row {sev_cls}" data-target="{card_id}" data-label="{filter_key}">'
                f'<a href="#{card_id}">'
                f'<span class="sev-dot"></span>'
                f'<span class="step-count">{step_count}-step</span>'
                f'<span class="dest-label">{dest_label}</span>'
                f'<span class="affected-count">{count_label}</span>'
                f'</a></li>'
            )
            content_cards.append(self._build_path_card(pg, cat_name, sev_cls, steps))

        parts = ['<div class="report-layout">']
        parts.append('<aside class="path-sidebar">')
        parts.append(f'<h4>Paths ({len(visible)})</h4>')
        if visible:
            parts.append('<input type="search" class="sidebar-filter" placeholder="Filter destinations…" aria-label="Filter paths">')
            parts.append('<ol class="sidebar-list">')
            parts.extend(sidebar_rows)
            parts.append('</ol>')
        else:
            parts.append('<p class="sidebar-empty">No paths in this category.</p>')
        parts.append('</aside>')

        parts.append('<section class="path-content">')
        parts.append(f'<h2><span class="badge {sev_cls}">{sev_lbl}</span>{_h(display_name)}</h2>')
        parts.extend(content_cards)
        parts.append('</section>')
        parts.append('</div>')

        return '\n'.join(parts)

    def _build_path_card(self, path_group, category, sev_cls, steps=None):
        path_string = path_group.get('path_string', '')
        count = path_group.get('count', 0)
        entities = path_group.get('entities', [])

        steps = steps if steps is not None else self._get_path_steps(path_string)
        edge_types = [s['edge'] for s in steps if s['edge']]

        card_id = self._path_card_id(category, path_string)
        sorted_ents = sorted(entities)
        self._client_report_data['pathGroups'][card_id] = {'entities': sorted_ents}

        parts = []
        parts.append(f'<div class="card {sev_cls} path-card" id="{card_id}" data-path="{_h(path_string)}">')

        last_node = steps[-1]['node'] if steps else ''
        last_type = steps[-1]['node_type'] if steps else ''
        dest_label = _h(last_node) + (f' ({_h(last_type)})' if last_type else '')

        # try both with and without @domain suffix
        dest_info = (self._dest_cache.get(last_node) or
                     self._dest_cache.get(last_node + '@' + self.domain) or
                     {})
        reason = dest_info.get('reason', '')

        affected_type = 'users' if 'Users' in category else 'computers'
        if count == 1 and entities:
            single_name = _h(entities[0].split('@')[0].rstrip('$').upper())
            parts.append(f'<h3>'
                         f'{len(edge_types)}-step escalation path to {dest_label}, '
                         f'affects {single_name}</h3>')
        else:
            parts.append(f'<h3>'
                         f'{len(edge_types)}-step escalation path to {dest_label} '
                         f'<span class="count-badge">{count} affected {affected_type}</span></h3>')

        dest_tip_parts = []
        if dest_info.get('type'):
            dest_tip_parts.append(f"Type: {_h(dest_info['type'])}")
        if dest_info.get('ca_active') is not None:
            if dest_info['ca_active']:
                tpl = dest_info.get('ca_template_count', 0)
                dest_tip_parts.append(f"Status: Active ({tpl} published templates)")
            else:
                dest_tip_parts.append("Status: Inactive")
        elif dest_info.get('enabled') is not None:
            status = 'Enabled' if dest_info['enabled'] else 'Disabled'
            dest_tip_parts.append(f"Status: {status}")
        if reason:
            dest_tip_parts.append(f"{_h(reason)}")
        if dest_info.get('samaccountname'):
            dest_tip_parts.append(f"sAMAccountName: {_h(dest_info['samaccountname'])}")
        if dest_info.get('domain'):
            dest_tip_parts.append(f"Domain: {_h(dest_info['domain'])}")
        if dest_info.get('operatingsystem'):
            dest_tip_parts.append(f"OS: {_h(dest_info['operatingsystem'])}")
        if dest_info.get('functionallevel'):
            dest_tip_parts.append(f"Functional Level: {_h(dest_info['functionallevel'])}")
        if dest_info.get('dnshostname') and dest_info['dnshostname'].upper() != last_node.split('@')[0].upper():
            dest_tip_parts.append(f"Hostname: {_h(dest_info['dnshostname'])}")
        if dest_info.get('caname'):
            dest_tip_parts.append(f"CA Name: {_h(dest_info['caname'])}")
        if dest_info.get('certname'):
            dest_tip_parts.append(f"Certificate: {_h(dest_info['certname'])}")
        if dest_info.get('displayname') and dest_info['displayname'].upper() != (dest_info.get('samaccountname') or '').upper():
            dest_tip_parts.append(f"Display Name: {_h(dest_info['displayname'])}")
        if dest_info.get('description'):
            dest_tip_parts.append(f"Description: {_h(dest_info['description'])}")
        dest_name_full = last_node + '@' + self.domain if '@' not in last_node else last_node
        dest_groups = self.destination_groups.get(dest_name_full) or self.destination_groups.get(last_node)
        if dest_groups:
            groups_html = _fmt_groups(dest_groups)
            if groups_html:
                dest_tip_parts.append(f"Groups: {groups_html}")
        dest_tip_html = '<br>'.join(dest_tip_parts).replace('"', '&quot;') if dest_tip_parts else ''

        cat_entry = _CATEGORIES.get(category)
        # single entity gets its own name on the source node, not "Users (1)"
        if count == 1 and entities:
            src_label = entities[0].split('@')[0].rstrip('$').upper()
            src_count = 0
        else:
            src_label = cat_entry[3] if cat_entry else 'Affected Entities'
            src_count = count
        # cap tooltip at _ENTITY_SOURCE_TOOLTIP_LIMIT entries
        if len(sorted_ents) <= _ENTITY_SOURCE_TOOLTIP_LIMIT:
            src_tip_text = '<br>'.join(_h(e) for e in sorted_ents)
        else:
            src_tip_text = '<br>'.join(_h(e) for e in sorted_ents[:_ENTITY_SOURCE_TOOLTIP_LIMIT])
            src_tip_text += f'<br>... and {len(sorted_ents) - _ENTITY_SOURCE_TOOLTIP_LIMIT} more'
        src_tip_html = src_tip_text.replace('"', '&quot;')
        parts.append(_build_path_svg(steps, source_label=src_label, source_count=src_count, dest_tip=dest_tip_html, source_tip=src_tip_html))

        unique_edges = list(dict.fromkeys(edge_types))  # preserves order, deduplicates
        edge_info_map = {edge: info for edge in unique_edges if (info := get_edge_info(edge))}

        what_text = self._build_what_narrative(steps, count, category, reason)
        final_edge = ''
        for s in reversed(steps):
            if s['edge'] and s['edge'] != 'MemberOf':
                final_edge = s['edge']
                break
        if not final_edge and steps:
            final_edge = steps[-1]['edge'] or ''
        impact = self._build_impact_sentence(final_edge, last_node, last_type, reason)
        overview = f'{what_text} {impact}' if what_text else impact
        parts.append(f'<details open><summary>Overview</summary><div class="info-section"><p>{overview}</p></div></details>')

        # Affected entities are rendered on first expansion from embedded JSON.
        affected_label = 'Users' if 'Users' in category else 'Computers'
        parts.append(f'<details class="affected-entities" data-card-id="{card_id}"><summary>Affected {affected_label} ({count})</summary>')
        parts.append('<div class="entity-list-status">Open to load affected entities.</div>')
        parts.append('<ul class="entity-list lazy-entity-list"></ul>')
        parts.append('</details>')

        final_target_key = (last_type or '').lower()

        def _mit_text(edge):
            info = edge_info_map[edge]
            # final edge gets a target-type-specific override when one exists
            if edge == final_edge and final_target_key:
                override = (info.get('mitigation_overrides') or {}).get(final_target_key)
                if override:
                    return override
            return info['mitigation']

        mitigation_sections = [
            f'<div class="info-section"><p><strong>{_h(e)}:</strong> {_h(_mit_text(e))}</p></div>'
            for e in unique_edges if e in edge_info_map
        ]

        if mitigation_sections:
            parts.append('<details><summary>Mitigation</summary>')
            parts.extend(mitigation_sections)
            parts.append('</details>')

        rep_details = self._find_representative(path_group, category)
        if rep_details:
            ps_steps = _generate_powershell_for_path(
                rep_details, self.domain,
                self.domain_controller, self.domain_sid
            )
            if ps_steps:
                parts.append('<details><summary>How to Confirm</summary>')
                parts.append(f'<div class="ps-context">These commands verify each step in the path. '
                             f'The first step uses a sample entity from the affected list above. '
                             f'Replace it with any affected entity to confirm the same path exists.</div>')
                for idx, step in enumerate(ps_steps, 1):
                    parts.append(f'<p class="step-header">Step {idx}</p>')
                    parts.append(_build_step_svg(step['source'], step['edge'], step['target']))
                    explain = _ps_step_explanation(step['edge'], step['source'], step['target'])
                    if explain.get('intro'):
                        parts.append(f'<p class="step-intro"><strong>What it checks:</strong> {explain["intro"]}</p>')
                    parts.append(f'<pre class="ps-cmd">{_h(step["command"])}</pre>')
                    if explain.get('confirmed_if'):
                        parts.append(f'<p class="step-confirm"><strong>Confirmed if</strong> {explain["confirmed_if"]}.</p>')
                parts.append('</details>')

        parts.append('</div>')  # card
        return '\n'.join(parts)



def main():
    import argparse
    parser = argparse.ArgumentParser(description='Generate client HTML report from AD Pathfinder audit JSON.')
    parser.add_argument('-json', required=True, help='Path to the domain audit JSON file.')
    parser.add_argument('-output', default=None, help='Output HTML path (default: derived from input).')
    args = parser.parse_args()

    json_path = getattr(args, 'json')
    output = args.output
    if not output:
        base = os.path.splitext(json_path)[0]
        if base.endswith('_domain_audit'):
            base = base[:-len('_domain_audit')]
        output = f"{base}_AD_report.html"

    gen = ClientReportGenerator(json_path=json_path)
    gen.generate(output)


if __name__ == '__main__':
    main()
