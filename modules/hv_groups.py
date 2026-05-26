"""Canonical high-value Active Directory group definitions.

Single source of truth for admin classification, escalation filtering, and
tooltip bolding. Group names match BloodHound storage (uppercase).
"""

# Strict privileged groups. Members hold admin-equivalent privilege and are
# classified as admin by the tool. Used by Neo4j Cypher queries (requires
# BloodHound's uppercase convention, e.g. 'DNSADMINS' not 'DnsAdmins').
ADMIN_GROUP_NAMES = [
    # Core AD privileged
    'DOMAIN ADMINS',
    'ENTERPRISE ADMINS',
    'SCHEMA ADMINS',
    'ADMINISTRATORS',
    'DOMAIN CONTROLLERS',
    'READ-ONLY DOMAIN CONTROLLERS',
    'ENTERPRISE READ-ONLY DOMAIN CONTROLLERS',
    'ACCOUNT OPERATORS',
    'SERVER OPERATORS',
    'BACKUP OPERATORS',
    'PRINT OPERATORS',
    'GROUP POLICY CREATOR OWNERS',
    # PKI / ADCS
    'KEY ADMINS',
    'ENTERPRISE KEY ADMINS',
    'CERT PUBLISHERS',
    'CERTIFICATE ADMINS',
    # DNS / DHCP
    'DNSADMINS',
    'DHCP ADMINISTRATORS',
    # Local / virtualization
    'CRYPTOGRAPHIC OPERATORS',
    'HYPER-V ADMINISTRATORS',
    'ACCESS CONTROL ASSISTANCE OPERATORS',
    # Exchange
    'EXCHANGE ORGANIZATION ADMINISTRATORS',
    'EXCHANGE TRUSTED SUBSYSTEM',
    'EXCHANGE WINDOWS PERMISSIONS',
    'ORGANIZATION MANAGEMENT',
]

# Non-privilege markers. Membership signals the account is considered worth
# protecting but does not grant privilege — excluded from admin classification
# but still shown in bold in tooltips and skipped during escalation analysis.
PROTECTED_MARKER_GROUPS = [
    'PROTECTED USERS',
]

# Uppercase set for visual/display matching (tooltip bolding). Includes markers.
HIGH_VALUE_GROUPS_UPPER = set(ADMIN_GROUP_NAMES) | set(PROTECTED_MARKER_GROUPS)

# Lowercase set for substring matching in escalation path filtering.
# Strict admin only — Protected Users handled separately by caller.
ADMIN_GROUPS_LOWER = {g.lower() for g in ADMIN_GROUP_NAMES}


def admin_groups_for_domain(domain):
    return [f"{name}@{domain}" for name in ADMIN_GROUP_NAMES]
