from __future__ import annotations

import configparser
import os
import stat
from dataclasses import dataclass, field
from typing import Optional

from .secret import Secret


NEO4J_URI_DEFAULT = "neo4j://localhost:7687"
BLOODHOUND_URL_DEFAULT = "http://localhost:8080"

DEFAULT_EXCLUDED_RELATIONSHIPS: tuple[str, ...] = (
    'LocalToComputer', 'Contains', 'RootCAFor', 'EnterpriseCAFor', 'PublishedTo',
    'DCFor', 'HostsCAService', 'NTAuthStoreFor', 'TrustedForNTAuth',
    'SameForestTrust', 'ProtectAdminGroups', 'ClaimSpecialIdentity',
    'MemberOfLocalGroup', 'HasSIDHistory', 'HasTrustKeys',
    'GetChanges', 'GetChangesAll', 'GetChangesInFilteredSet',
    'OwnsRaw', 'WriteOwnerRaw',
    'Enroll', 'EnrollOnBehalfOf', 'WritePKINameFlag', 'WritePKIEnrollmentFlag',
    'WriteCertificateMappingAccess',
    'ADCSESC1', 'ADCSESC2', 'ADCSESC3', 'ADCSESC4', 'ADCSESC6a', 'ADCSESC6b',
    'ADCSESC7', 'ADCSESC8', 'ADCSESC9a', 'ADCSESC9b',
    'ExecuteDCOM', 'RemoteInteractiveLogonRight', 'GPLink', 'HasSession',
    'GoldenCert', 'ManageCA', 'ManageCertificates',
    'CoerceAndRelayNTLMToADCS', 'CoerceAndRelayNTLMToLDAP', 'CoerceAndRelayNTLMToLDAPS',
)


@dataclass
class ResolvedConfig:
    neo4j_uri: str = NEO4J_URI_DEFAULT
    neo4j_username: Optional[str] = None
    neo4j_password: Optional[Secret] = None
    bh_url: str = BLOODHOUND_URL_DEFAULT
    bh_username: Optional[str] = None
    bh_password: Optional[Secret] = None
    bh_enabled: bool = False
    bh_configured: bool = False
    hashcat_file_path: Optional[str] = None
    excluded_relationships: tuple[str, ...] = field(
        default_factory=lambda: tuple(DEFAULT_EXCLUDED_RELATIONSHIPS)
    )


def _env_str(name: str) -> Optional[str]:
    value = os.environ.get(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


_ENV_BOOL_TRUE = frozenset({"1", "true", "yes", "on"})
_ENV_BOOL_FALSE = frozenset({"0", "false", "no", "off"})


def _env_bool(name: str) -> Optional[bool]:
    value = _env_str(name)
    if value is None:
        return None
    lowered = value.lower()
    if lowered in _ENV_BOOL_TRUE:
        return True
    if lowered in _ENV_BOOL_FALSE:
        return False
    print(
        f"Warning: {name}={value!r} is not a valid boolean; ignoring. "
        f"Use one of 1/true/yes/on or 0/false/no/off."
    )
    return None


def _config_get(config: configparser.ConfigParser, section: str, option: str) -> Optional[str]:
    value = config.get(section, option, fallback=None) if config.has_section(section) else None
    if value is None:
        return None
    value = value.strip()
    return value or None


def _resolve_excluded_relationships(config: configparser.ConfigParser) -> tuple[str, ...]:
    if not (config.has_section("EXCLUSIONS")
            and config.has_option("EXCLUSIONS", "excluded_relationships")):
        return tuple(DEFAULT_EXCLUDED_RELATIONSHIPS)

    raw = config.get("EXCLUSIONS", "excluded_relationships")
    tokens = (token.strip() for chunk in raw.splitlines() for token in chunk.split(","))
    seen: dict[str, str] = {}
    for token in tokens:
        if token and token.lower() not in seen:
            seen[token.lower()] = token
    return tuple(seen.values())


def _warn_if_world_readable(config_file: str) -> None:
    try:
        mode = os.stat(config_file).st_mode
    except OSError:
        return
    if not stat.S_ISREG(mode):
        return
    if mode & 0o077:
        print(
            f"Warning: {config_file} is readable beyond owner "
            f"(mode {stat.filemode(mode)}). Run `chmod 600 {config_file}` "
            f"to lock it down."
        )


def load(config_file: str = "config.ini") -> ResolvedConfig:
    config = configparser.ConfigParser()
    if os.path.exists(config_file):
        config.read(config_file)
        _warn_if_world_readable(config_file)

    neo4j_uri = (
        _env_str("ADPF_NEO4J_URI")
        or _config_get(config, "NEO4J", "uri")
        or NEO4J_URI_DEFAULT
    )
    neo4j_username = _env_str("ADPF_NEO4J_USERNAME") or _config_get(config, "NEO4J", "username")
    neo4j_password_raw = _env_str("ADPF_NEO4J_PASSWORD") or _config_get(config, "NEO4J", "password")
    neo4j_password = Secret(neo4j_password_raw) if neo4j_password_raw is not None else None

    bh_url_raw = (
        _env_str("ADPF_BLOODHOUND_URL")
        or _config_get(config, "BLOODHOUND", "url")
        or BLOODHOUND_URL_DEFAULT
    )
    bh_url = bh_url_raw.rstrip("/")
    bh_username = _env_str("ADPF_BLOODHOUND_USERNAME") or _config_get(config, "BLOODHOUND", "username")
    bh_password_raw = _env_str("ADPF_BLOODHOUND_PASSWORD") or _config_get(config, "BLOODHOUND", "password")
    bh_password = Secret(bh_password_raw) if bh_password_raw is not None else None

    bh_enabled_env = _env_bool("ADPF_BLOODHOUND_ENABLED")
    if bh_enabled_env is not None:
        bh_enabled = bh_enabled_env
    elif config.has_section("BLOODHOUND"):
        # fallback=True for legacy configs that pre-date the explicit `enabled` key
        bh_enabled = config.getboolean("BLOODHOUND", "enabled", fallback=True)
    else:
        bh_enabled = False
    bh_configured = bh_enabled_env is not None or config.has_section("BLOODHOUND")

    hashcat_path = _env_str("ADPF_HASHCAT_FILE_PATH") or _config_get(config, "HASHCAT", "file_path")
    if hashcat_path and not os.path.isfile(hashcat_path):
        hashcat_path = None

    return ResolvedConfig(
        neo4j_uri=neo4j_uri,
        neo4j_username=neo4j_username,
        neo4j_password=neo4j_password,
        bh_url=bh_url,
        bh_username=bh_username,
        bh_password=bh_password,
        bh_enabled=bh_enabled,
        bh_configured=bh_configured,
        hashcat_file_path=hashcat_path,
        excluded_relationships=_resolve_excluded_relationships(config),
    )
