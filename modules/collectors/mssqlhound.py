from typing import Optional

from modules.opengraph_collectors import (
    CollectorManifest,
    register_collector_manifest,
)


def _mssql_identity(json_data: dict) -> Optional[str]:
    try:
        nodes = json_data.get("graph", {}).get("nodes", [])
        for node in nodes:
            if "MSSQL_Server" not in node.get("kinds", []):
                continue

            properties = node.get("properties", {})
            server_name = properties.get("name", "")
            if not server_name:
                return None

            configured_hostname = properties.get("hostname") or properties.get("fqdn")
            if ":" in server_name:
                hostname, identifier = server_name.rsplit(":", 1)
                id_type = "port" if identifier.isdigit() else "instance"
            else:
                hostname = server_name
                id_type = "host"
                identifier = ""

            hostname = str(configured_hostname or hostname).lower()
            instance_name = str(properties.get("instanceName") or "").strip()
            if instance_name and instance_name.upper() not in {"MSSQLSERVER", "DEFAULT"}:
                id_type = "instance"
                identifier = instance_name

            return f"{hostname}|{id_type}|{str(identifier).lower()}"
        return None
    except Exception:
        return None


MSSQLHOUND_MANIFEST = CollectorManifest(
    source_kind="MSSQL_Base",
    principal_kinds=("MSSQL_Server",),
    owned_kinds=(
        "MSSQL_Database",
        "MSSQL_DatabaseRole",
        "MSSQL_DatabaseUser",
        "MSSQL_Login",
        "MSSQL_Server",
        "MSSQL_ServerRole",
    ),
    merge_strategy="opengraph",
    identity_fn=_mssql_identity,
)


register_collector_manifest(MSSQLHOUND_MANIFEST)
