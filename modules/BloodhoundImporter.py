import os
import zipfile
import requests
import json
import time
import tempfile
from pathlib import Path
from typing import List, Optional, Dict, Tuple


# AD principal kinds that SharpHound owns. Companion files from MSSQLHound
# and ConfigManBearPig duplicate these node IDs in OpenGraph format with
# different name/casing conventions; without filtering, BH CE's MERGE on
# (label, objectid) overwrites SharpHound properties (notably `name`).
_AD_KINDS = frozenset({'User', 'Computer', 'Group', 'Base'})

# Allowlist of properties from AD-companion files that we keep before upload.
# Anything outside this set is dropped on AD-only nodes so the merge can only
# enhance SharpHound nodes with additive fields, never overwrite AD attributes.
#
# Allowlist (not denylist) is deliberate: if a future companion adds a new
# AD-overlap property (e.g. `displayName`, `description`), a denylist might
# miss it and silently corrupt SharpHound data. With an allowlist, the worst
# case is dropping a new useful property — visible as missing data — rather
# than silently overwriting SharpHound — invisible until it breaks a check.
# The SCCM* prefix gives forward-compat for new ConfigManBearPig fields.
_AD_COMPANION_ADDITIVE_KEYS = frozenset({
    'SMBSigningRequired',           # RemoteRegistry SMB signing posture
    'collectionSource',             # provenance: which check produced the node
    'disableLoopbackCheck',         # NTLM relay viability indicator
    'restrictReceivingNtlmTraffic', # NTLM relay viability indicator
    'storedInSCCMSite',             # ConfigManBearPig SCCM membership flag
})


def _is_additive_companion_property(key: str) -> bool:
    if key.startswith('SCCM'):
        return True
    return key in _AD_COMPANION_ADDITIVE_KEYS


# Labels safe to interpolate into _merge_orphan_stubs Cypher. The label is
# f-stringed into the query, so accepting an arbitrary value would be a
# Cypher-injection footgun; restrict to the two we actually emit.
_ORPHAN_STUB_LABELS = frozenset({'SCCM_Base', 'MSSQL_Base'})

# (path, category, parsed_data) — populated once per file at import time so
# downstream stages don't re-open and re-parse the same JSON.
JsonEntry = Tuple[Path, str, Optional[dict]]


# Static seed data from ConfigManBearPig — registers custom SCCM/MSSQL
# node and edge kinds in BloodHound CE.  Must be uploaded before any SCCM
# collection data, otherwise BH CE silently drops unknown kinds.
_SCCM_SEED_NODE_ID = "9c3a1f7a-1d6b-4d87-b61b-1c3b7a9e4f01"
_SCCM_SEED_EDGE_KINDS = [
    "LocalAdminRequired", "CoerceAndRelayToAdminService",
    "CoerceAndRelayToMSSQL", "CoerceAndRelaytoSMB", "CoerceAndRelayToSMB",
    "HasSession",
    "MSSQL_Contains", "MSSQL_ControlDB", "MSSQL_ControlServer",
    "MSSQL_ExecuteOnHost", "MSSQL_GetAdminTGS", "MSSQL_GetTGS",
    "MSSQL_HasLogin", "MSSQL_HostFor", "MSSQL_IsMappedTo",
    "MSSQL_LinkedAsAdmin", "MSSQL_MemberOf", "MSSQL_ServiceAccountFor",
    "SameHostAs", "SCCM_AdminsReplicatedTo", "SCCM_AllPermissions",
    "SCCM_ApplicationAdministrator", "SCCM_AssignAllPermissions",
    "SCCM_AssignSpecificPermissions", "SCCM_Contains",
    "SCCM_FullAdministrator", "SCCM_HasADLastLogonUser",
    "SCCM_HasClient", "SCCM_HasCurrentUser", "SCCM_HasMember",
    "SCCM_HasNetworkAccessAccount", "SCCM_HasPrimaryUser",
    "SCCM_HasStoredAccount", "SCCM_IsAssigned", "SCCM_IsMappedTo",
]


def _build_sccm_seed() -> dict:
    ref = {"value": _SCCM_SEED_NODE_ID}
    return {
        "metadata": {"source_kind": "SCCM_Seed"},
        "graph": {
            "nodes": [{"kinds": ["IgnoreMe"], "id": _SCCM_SEED_NODE_ID,
                        "properties": {"name": "IgnoreMe"}}],
            "edges": [{"kind": k, "start": ref, "end": ref}
                      for k in _SCCM_SEED_EDGE_KINDS],
        },
    }


def is_mssql_data(json_data: dict) -> bool:
    try:
        nodes = json_data.get('graph', {}).get('nodes', [])
        return any('MSSQL_Server' in node.get('kinds', []) for node in nodes)
    except Exception:
        return False

def get_mssql_server_identifier(json_data: dict) -> Optional[str]:
    try:
        nodes = json_data.get('graph', {}).get('nodes', [])
        for node in nodes:
            if 'MSSQL_Server' in node.get('kinds', []):
                server_name = node.get('properties', {}).get('name', '')
                if ':' in server_name:
                    hostname, identifier = server_name.rsplit(':', 1)
                    id_type = 'port' if identifier.isdigit() else 'instance'
                    return f"{hostname.lower()}|{id_type}"
        return None
    except Exception:
        return None

class BloodhoundImporter:
    def __init__(self, neo4j_conn, bloodhound_username: Optional[str] = None,
                 bloodhound_password: Optional[str] = None,
                 base_url: Optional[str] = None):
        self.connection = neo4j_conn
        self.user = bloodhound_username
        self.pwd = bloodhound_password
        self.base_url = (base_url or "http://localhost:8080").rstrip('/')
        self.jwt = ""

    def import_zip(self, zip_paths) -> bool:
        if isinstance(zip_paths, str):
            zip_paths = [zip_paths]

        validated_paths = []
        for zip_path in zip_paths:
            zip_path = Path(zip_path).resolve()
            if not zip_path.is_file() or zip_path.suffix != '.zip':
                print(f"Invalid ZIP file path: {zip_path}")
                return False
            validated_paths.append(zip_path)

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                extract_dir = Path(temp_dir)

                all_json_files = []
                for idx, zip_path in enumerate(validated_paths):
                    zip_extract_dir = extract_dir / f"zip_{idx}"
                    zip_extract_dir.mkdir(exist_ok=True)
                    json_files = self._extract_zip(zip_path, zip_extract_dir)
                    if json_files:
                        all_json_files.extend(json_files)

                if not all_json_files:
                    print("No JSON files found in zip archive(s)")
                    return False

                # Single classify pass — every downstream stage reuses these
                # entries instead of re-opening and re-parsing the JSON.
                entries: List[JsonEntry] = [
                    (fp, *self._classify_json_file(fp)) for fp in all_json_files
                ]
                entries = self._deduplicate_mssql_files(entries)

                self._authenticate()

                # AD-companion files augment SharpHound nodes (post-filter), so
                # surface them under the BloodHound count rather than as a
                # separate visible category.
                counts: Dict[str, int] = {}
                for _, cat, _ in entries:
                    counts[cat] = counts.get(cat, 0) + 1
                parts = []
                sharphound_total = counts.get('sharphound', 0) + counts.get('ad_companion', 0)
                if sharphound_total:
                    parts.append(f"{sharphound_total} BloodHound")
                sccm_total = counts.get('sccm_seed', 0) + counts.get('sccm', 0)
                if sccm_total:
                    parts.append(f"{sccm_total} SCCM")
                mssql_total = counts.get('mssql_seed', 0) + counts.get('mssql', 0)
                if mssql_total:
                    parts.append(f"{mssql_total} MSSQL")
                print(f"[*] Importing {len(entries)} files ({', '.join(parts)})")

                self._upload_json_files(entries)

                print("[+] Import completed successfully")
                return True

        except Exception as e:
            print(f"Error importing BloodHound data: {str(e)}")
            return False

    def _authenticate(self) -> None:
        auth_data = {
            "login_method": "secret",
            "username": self.user,
            "secret": self.pwd
        }
        auth_url = f"{self.base_url}/api/v2/login"
        response = requests.post(auth_url, json=auth_data)

        if response.status_code != 200:
            raise Exception(f"Authentication failed: {response.text}")

        try:
            self.jwt = response.json()["data"]["session_token"]
        except (KeyError, json.JSONDecodeError) as e:
            raise Exception(f"Failed to parse authentication response: {str(e)}")

    def _extract_zip(self, zip_path: Path, extract_dir: Path) -> List[Path]:
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
        except zipfile.BadZipFile:
            raise Exception("The provided file is not a valid ZIP archive.")

        json_files = []
        for file in os.listdir(extract_dir):
            if file.endswith('.json'):
                json_file_path = extract_dir / file
                json_files.append(json_file_path)

        return json_files

    def _classify_json_file(self, file_path: Path) -> tuple:
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                data = json.load(f)
            source_kind = data.get('metadata', {}).get('source_kind', '')
            nodes = data.get('graph', {}).get('nodes', [])

            # SCCM seed: must be ingested first to register custom kinds
            if source_kind == 'SCCM_Seed':
                return 'sccm_seed', data
            # SCCM data: source_kind containing 'SCCM' (even if it has MSSQL nodes)
            if 'SCCM' in source_kind:
                return 'sccm', data
            # MSSQLHound seed: registers OpenGraph edge kinds before MSSQL data
            if source_kind == 'MSSQL' and nodes and all(
                set(n.get('kinds', [])) == {'IgnoreMe'} for n in nodes
            ):
                return 'mssql_seed', data
            # MSSQLHound: has MSSQL_Server nodes (standalone MSSQL collector)
            if is_mssql_data(data):
                return 'mssql', data
            # AD companion: OpenGraph file where every node is AD-only.
            # Conservative: a single non-AD kind on any node disqualifies the
            # whole file so SCCM/MSSQL data files never accidentally land here.
            if nodes and all(set(n.get('kinds', [])).issubset(_AD_KINDS) for n in nodes):
                return 'ad_companion', data
        except Exception as e:
            print(f"Warning: zip classification failed for {file_path.name}, defaulting to sharphound: {e}")
        return 'sharphound', None

    def _filter_ad_companion_properties(self, file_path: Path, data: dict) -> Optional[bytes]:
        # strip AD-overlap props so MERGE only adds SCCM*/SMBSigning fields, never clobbers SharpHound data
        nodes = data.get('graph', {}).get('nodes', [])
        out_nodes: List[dict] = []

        for node in nodes:
            if not set(node.get('kinds', [])).issubset(_AD_KINDS):
                out_nodes.append(node)
                continue
            props = node.get('properties', {})
            kept = {k: v for k, v in props.items()
                    if _is_additive_companion_property(k)}
            if not kept:
                continue
            out_nodes.append({**node, 'properties': kept})

        if not out_nodes:
            return None

        data['graph']['nodes'] = out_nodes
        return json.dumps(data).encode('utf-8')

    def _upload_json_files(self, entries: List[JsonEntry]) -> None:
        # order matters: seeds register custom kinds before data that references them
        headers = {
            "User-Agent": "bh-automation",
            "Authorization": f"Bearer {self.jwt}",
            "Content-Type": "application/json",
        }

        # Each upload payload is (display_name, body_bytes_or_path).
        # body=Path -> read at upload time; body=bytes -> in-memory (filtered
        # companion or auto-generated seed).
        buckets: Dict[str, List[Tuple[str, object]]] = {
            'sharphound': [], 'ad_companion': [], 'sccm_seed': [], 'sccm': [],
            'mssql_seed': [], 'mssql': [],
        }
        for path, category, data in entries:
            if category == 'ad_companion' and data is not None:
                body = self._filter_ad_companion_properties(path, data)
                if body is not None:
                    buckets['ad_companion'].append((path.name, body))
            else:
                buckets[category].append((path.name, path))

        if buckets['sccm'] and not buckets['sccm_seed']:
            seed_body = json.dumps(_build_sccm_seed()).encode('utf-8')
            buckets['sccm_seed'].append(('seed_data.json', seed_body))

        upload_order = ['sharphound', 'ad_companion', 'sccm_seed', 'sccm',
                        'mssql_seed', 'mssql']
        for category in upload_order:
            payloads = buckets[category]
            if not payloads:
                continue
            upload_id = self._start_upload_batch(headers)
            for name, body in payloads:
                self._upload_single_file(name, body, upload_id, headers)
            self._complete_upload_batch(upload_id, headers)
            self._wait_for_ingestion(upload_id, headers)

        # Link orphan SCCM/MSSQL principal nodes to their AD counterparts.
        # MSSQLHound and ConfigManBearPig reference AD principals by SID but
        # ship them with custom kinds (MSSQL_Login, SCCM_Base, ...). BH CE's
        # MERGE keys on (label, objectid), so these end up as separate nodes
        # from the existing SharpHound :User/:Computer/:Group with the same
        # objectid. This step finds those orphans, moves their relationships
        # onto the real AD node, and deletes the orphan, so traversal queries
        # (SCCM Database Compromise, MSSQL Privilege Escalation, MSSQL Login
        # Impersonation, ...) work end-to-end.
        if buckets['sccm']:
            self._merge_orphan_stubs('SCCM_Base')
        if buckets['mssql']:
            self._merge_orphan_stubs('MSSQL_Base')
            # Pre-SID MSSQLHound builds emit MSSQL_Server.objectid as
            # 'host:port' or 'host\\instance:port' and don't ship a
            # MSSQL_HostFor edge. Wire one up here from MSSQL_Server.name
            # so downstream checks can stay strictly SID-based via the
            # Computer-[:MSSQL_HostFor]->MSSQL_Server traversal regardless
            # of collector version.
            self._link_legacy_mssql_servers()

    def _merge_orphan_stubs(self, label: str) -> None:
        # don't copy the collector label onto the AD node — account_analysis would mis-classify it as a stub
        if label not in _ORPHAN_STUB_LABELS:
            raise ValueError(f"Unsupported orphan-merge label: {label!r}")
        pairs = self.connection.query(f"""
            MATCH (stub:{label}) WHERE size(labels(stub)) = 1
            WITH stub
            MATCH (real) WHERE real.objectid = stub.objectid
              AND (real:User OR real:Computer OR real:Group)
            RETURN count(*) as c
        """)
        if not pairs or not pairs[0].get('c'):
            return

        rel_types = self.connection.query(f"""
            MATCH (stub:{label})-[r]-()
            WHERE size(labels(stub)) = 1
            RETURN DISTINCT type(r) as rtype
        """)
        for rt in (rel_types or []):
            rtype = rt['rtype']
            self.connection.query(f"""
                MATCH (stub:{label})-[old:`{rtype}`]->(target)
                WHERE size(labels(stub)) = 1
                WITH stub, old, target
                MATCH (real) WHERE real.objectid = stub.objectid
                  AND (real:User OR real:Computer OR real:Group)
                CREATE (real)-[new:`{rtype}`]->(target)
                SET new = properties(old)
                DELETE old
            """)
            self.connection.query(f"""
                MATCH (source)-[old:`{rtype}`]->(stub:{label})
                WHERE size(labels(stub)) = 1
                WITH source, old, stub
                MATCH (real) WHERE real.objectid = stub.objectid
                  AND (real:User OR real:Computer OR real:Group)
                CREATE (source)-[new:`{rtype}`]->(real)
                SET new = properties(old)
                DELETE old
            """)

        self.connection.query(f"""
            MATCH (stub:{label})
            WHERE size(labels(stub)) = 1
            WITH stub
            MATCH (real) WHERE real.objectid = stub.objectid
              AND (real:User OR real:Computer OR real:Group)
            DETACH DELETE stub
        """)

    def _link_legacy_mssql_servers(self) -> None:
        # older MSSQLHound doesn't emit MSSQL_HostFor — resolve from name at import so runtime stays SID-based
        result = self.connection.query("""
            MATCH (s:MSSQL_Server)
            WHERE NOT EXISTS { MATCH (:Computer)-[:MSSQL_HostFor]->(s) }
              AND s.name IS NOT NULL
            WITH s, toLower(split(s.name, ':')[0]) as host_name
            WHERE host_name <> ''
            OPTIONAL MATCH (c:Computer)
            WHERE toLower(c.dnsHostName) = host_name OR toLower(c.name) = host_name
            WITH s, collect(c) as candidates
            WHERE size(candidates) = 1
            WITH s, candidates[0] as c
            MERGE (c)-[:MSSQL_HostFor]->(s)
            RETURN count(*) as linked
        """)
    def _start_upload_batch(self, headers: Dict[str, str]) -> str:
        url = f"{self.base_url}/api/v2/file-upload/start"
        response = requests.post(url, headers=headers)

        if response.status_code not in (200, 201):
            raise Exception(f"Failed to start upload batch: {response.status_code}")

        return response.json()["data"]["id"]

    def _upload_single_file(self, name: str, body, upload_id: str, headers: Dict[str, str]) -> None:
        if isinstance(body, Path):
            with open(body, "r", encoding="utf-8-sig") as f:
                body = f.read().encode("utf-8")

        url = f"{self.base_url}/api/v2/file-upload/{upload_id}"
        response = requests.post(url, headers=headers, data=body)

        if response.status_code not in (200, 202):
            raise Exception(f"Failed to upload {name}: HTTP {response.status_code}")

    def _complete_upload_batch(self, upload_id: str, headers: Dict[str, str]) -> None:
        url = f"{self.base_url}/api/v2/file-upload/{upload_id}/end"
        response = requests.post(url, headers=headers)

        if response.status_code != 200:
            raise Exception("Failed to complete upload batch")

    def _deduplicate_mssql_files(self, entries: List[JsonEntry]) -> List[JsonEntry]:
        # prefer instance-name copy over port copy when both exist for the same host
        mssql_by_id: Dict[str, JsonEntry] = {}
        passthrough: List[JsonEntry] = []

        for entry in entries:
            _, category, data = entry
            if category != 'mssql' or data is None:
                passthrough.append(entry)
                continue
            identifier = get_mssql_server_identifier(data)
            if identifier:
                mssql_by_id[identifier] = entry
            else:
                passthrough.append(entry)

        kept = list(passthrough)
        hostnames = {key.split('|')[0] for key in mssql_by_id}
        for hostname in hostnames:
            instance = mssql_by_id.get(f"{hostname}|instance")
            port = mssql_by_id.get(f"{hostname}|port")
            kept.append(instance or port)
        return kept

    # BH CE upload statuses that mean we should stop the import.
    # "Complete" and "Partially Completed" are handled inline because they
    # need different messaging (silent vs notice) — Partially Completed
    # means data ingested but post-analysis hit a non-fatal error, and the
    # stub-merge step can still recover from that.
    _ABORT_STATUSES = frozenset({"Failed", "Canceled", "Timed Out"})

    def _wait_for_ingestion(self, upload_id: str, headers: Dict[str, str]) -> None:
        # raises on failure so caller doesn't merge against a broken graph
        status_url = f"{self.base_url}/api/v2/file-upload?skip=0&limit=10&sort_by=-id"
        check_interval = 5

        while True:
            response = requests.get(status_url, headers=headers)
            if response.status_code != 200:
                raise Exception("Failed to check ingestion status")

            try:
                data = response.json()["data"]
                if not data:
                    break

                latest_status = data[0]
                status_message = latest_status.get('status_message', '')
                status_id = latest_status.get('id')

                if status_id == upload_id:
                    if status_message == "Complete":
                        break
                    if status_message == "Partially Completed":
                        print(f"[!] BH CE ingestion ended 'Partially Completed' "
                              f"for upload {upload_id} - data ingested but "
                              f"post-analysis was incomplete; continuing")
                        break
                    if status_message in self._ABORT_STATUSES:
                        raise Exception(
                            f"BH CE ingestion ended in '{status_message}' "
                            f"for upload {upload_id} - aborting import"
                        )
                    if "failed to ingest as JSON Content" in status_message:
                        raise Exception(
                            f"BH CE could not parse upload {upload_id}: "
                            f"{status_message}"
                        )
            except (KeyError, json.JSONDecodeError) as e:
                raise Exception(f"Failed to parse ingestion status response: {str(e)}")

            time.sleep(check_interval)

    def clear_database(self) -> bool:
        try:
            self._authenticate()

            url = f"{self.base_url}/api/v2/clear-database"
            headers = {
                "User-Agent": "bh-automation",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.jwt}"
            }

            data = {
                "deleteCollectedGraphData": True
            }

            response = requests.post(url, headers=headers, json=data)
            if response.status_code == 204:
                print("[+] Request successfully initiated.")
                return True
            else:
                print(f"[-] Failed to clear Neo4j database. Status code: {response.status_code}\n{response.text}")
                return False
        except Exception as e:
            print(f"Error clearing BloodHound data: {str(e)}")
            return False

    def mark_as_owned(self, cracked_users: List, ntds_file_path: str) -> None:
        if self.jwt == "":
            self._authenticate()

        from .neo4j_data import Neo4jData
        neo4j_data = Neo4jData(self.connection)

        domain_sid_base = neo4j_data.get_domain_sid_pattern()
        if not domain_sid_base:
            print("[-] Failed to get domain SID pattern")
            return

        username_to_sid = self._build_sid_mapping(ntds_file_path, domain_sid_base)
        if not username_to_sid:
            print("[-] Failed to build username to SID mapping")
            return

        sids_to_mark = set()
        sid_to_password_map = {}

        cracked_accounts = getattr(self, 'cracked_accounts', {})

        for user in cracked_users:
            username = user.lower()

            if username in username_to_sid:
                sid = username_to_sid[username]
                sids_to_mark.add(sid)

                if username in cracked_accounts:
                    password = cracked_accounts[username]
                    if password == "":
                        password = "blank"
                    sid_to_password_map[sid] = password

        if not sids_to_mark:
            print("[-] No valid SIDs found to mark as owned")
            return

        if sid_to_password_map:
            neo4j_data.update_user_passwords_by_sid(sid_to_password_map)

        asset_group_id = 2
        url = f"{self.base_url}/api/v2/asset-groups/{asset_group_id}/selectors"
        headers = {
            "User-Agent": "bh-automation",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.jwt}"
        }

        data = [
            {
                "action": "add",
                "selector_name": sid,
                "sid": sid,
            }
            for sid in sids_to_mark
        ]

        response = requests.put(url, headers=headers, json=data)

        if response.status_code == 201:
            print("[+] Marked all accounts as owned in BloodHound.")
        else:
            print(f"[-] Failed to mark as owned. Status code: {response.status_code}\n{response.text}")

        response.raise_for_status()

    def _build_sid_mapping(self, ntds_file_path: str, domain_sid_base: str) -> Dict[str, str]:
        username_to_sid = {}

        try:
            with open(ntds_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()

                    if not line or ':' not in line:
                        continue

                    parts = line.split(':')

                    if len(parts) >= 2:
                        full_username = parts[0]
                        rid = parts[1]

                        username = full_username.split('\\')[-1].lower()

                        if rid.isdigit():
                            sid = f"{domain_sid_base}-{rid}"
                            username_to_sid[username] = sid

                return username_to_sid

        except Exception as e:
            print(f"[-] Failed to read NTDS file: {e}")
            return {}
