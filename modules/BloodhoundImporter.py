import os
import zipfile
import requests
import json
import time
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Dict, Set, Tuple

from .opengraph_contracts import (
    evaluate_opengraph_requirements,
    prime_from_checks,
)
from .opengraph_collectors import (
    CollectorManifest,
    prime_from_collectors,
    registered_manifests,
)
from .opengraph_identifiers import (
    reserved_labels,
    safe_cypher_identifier,
)
from .mssql_post_import import (
    canonicalize_mssql_linked_server_edges,
    dedupe_mssql_servers,
)


_NEO4J_PROPERTY_SCALARS = (str, int, float, bool)

# (path, category, parsed_data) — populated once per file at import time so
# downstream stages don't re-open and re-parse the same JSON.
JsonEntry = Tuple[Path, str, Optional[dict]]
OpenGraphPayload = Tuple[str, dict, str]


@dataclass
class EndpointReference:
    match_by: str
    value: Optional[str] = None
    property_matchers: Tuple[dict, ...] = ()
    label: Optional[str] = None


def _normalise_neo4j_properties(
    properties: dict,
    dropped_keys: Optional[Set[str]] = None,
) -> dict:
    normalised = {}
    for key, value in (properties or {}).items():
        if not isinstance(key, str) or value is None:
            if dropped_keys is not None:
                dropped_keys.add(repr(key) if not isinstance(key, str) else key)
            continue
        if isinstance(value, _NEO4J_PROPERTY_SCALARS):
            normalised[key] = value
        elif isinstance(value, (list, tuple)):
            items = list(value)
            item_types = {type(item) for item in items}
            if (
                all(isinstance(item, _NEO4J_PROPERTY_SCALARS) for item in items)
                and len(item_types) <= 1
            ):
                normalised[key] = items
            elif dropped_keys is not None:
                dropped_keys.add(key)
        elif dropped_keys is not None:
            dropped_keys.add(key)
    return normalised


class BloodhoundImporter:
    def __init__(self, neo4j_conn, bloodhound_username: Optional[str] = None,
                 bloodhound_password: Optional[str] = None,
                 base_url: Optional[str] = None,
                 ingestion_timeout_seconds: Optional[int] = None,
                 request_timeout_seconds: Optional[int] = None,
                 diagnostics=None):
        self.connection = neo4j_conn
        self.user = bloodhound_username
        self.pwd = bloodhound_password
        self.base_url = (base_url or "http://localhost:8080").rstrip('/')
        self._diagnostics = diagnostics
        self.jwt = ""
        self.ingestion_timeout_seconds = self._resolve_ingestion_timeout(
            ingestion_timeout_seconds
        )
        self.request_timeout_seconds = self._resolve_request_timeout(
            request_timeout_seconds
        )

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
                # Fail fast before authentication, dedupe, and network I/O so
                # a malformed plug-in payload cannot trigger a BH CE login.
                self._validate_opengraph_entries(entries)
                entries = self._deduplicate_by_identity(entries)

                self._authenticate()

                counts: Dict[str, int] = {}
                for _, cat, _ in entries:
                    counts[cat] = counts.get(cat, 0) + 1
                parts = []
                bloodhound_total = counts.get('sharphound', 0)
                if bloodhound_total:
                    parts.append(f"{bloodhound_total} BloodHound")
                opengraph_total = counts.get('ad_companion', 0) + counts.get('opengraph', 0)
                if opengraph_total:
                    parts.append(f"{opengraph_total} OpenGraph")
                seed_total = counts.get('seed', 0)
                if seed_total:
                    parts.append(f"{seed_total} seed skipped")
                print(f"[*] Importing {len(entries)} files ({', '.join(parts)})")

                self._upload_json_files(entries, validate_raw=False)

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
        response = requests.post(
            auth_url,
            json=auth_data,
            timeout=self.request_timeout_seconds,
        )

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

        return sorted(
            path for path in extract_dir.rglob('*.json')
            if path.is_file()
        )

    def _classify_json_file(self, file_path: Path) -> tuple:
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                data = json.load(f)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"JSON {file_path.name}: invalid JSON at line "
                f"{exc.lineno}, column {exc.colno}: {exc.msg}"
            ) from exc

        if not isinstance(data, dict):
            return 'sharphound', None
        if 'graph' not in data:
            if self._has_opengraph_sentinel_without_graph(data):
                return 'opengraph', data
            return 'sharphound', None

        graph = data.get('graph')
        if not isinstance(graph, dict):
            return 'opengraph', data
        nodes = graph.get('nodes', [])
        if not isinstance(nodes, list):
            return 'opengraph', data
        node_kind_sets = []
        for node in nodes:
            if not isinstance(node, dict):
                return 'opengraph', data
            kinds = node.get('kinds', [])
            if not isinstance(kinds, list):
                return 'opengraph', data
            if not all(isinstance(kind, str) for kind in kinds):
                return 'opengraph', data
            node_kind_sets.append(set(kinds))

        if nodes and all(kinds == {'IgnoreMe'} for kinds in node_kind_sets):
            return 'seed', data
        manifest = self._select_collector_manifest(data, node_kind_sets)
        if manifest and manifest.merge_strategy == 'companion_additive':
            return 'ad_companion', data
        return 'opengraph', data

    def _select_collector_manifest(
        self,
        data: dict,
        node_kind_sets: Optional[List[Set[str]]] = None,
    ) -> Optional[CollectorManifest]:
        prime_from_collectors()
        graph = data.get('graph', {})
        if node_kind_sets is None:
            nodes = graph.get('nodes', [])
            node_kind_sets = []
            for node in nodes:
                if not isinstance(node, dict):
                    return None
                kinds = node.get('kinds', [])
                if not isinstance(kinds, list) or not all(
                    isinstance(kind, str) for kind in kinds
                ):
                    return None
                node_kind_sets.append(set(kinds))

        matches = [
            manifest
            for manifest in registered_manifests()
            if self._manifest_matches_node_kind_sets(manifest, node_kind_sets)
        ]
        if not matches:
            return None

        metadata = data.get('metadata', {})
        source_kind = ''
        if isinstance(metadata, dict):
            source_kind = metadata.get('source_kind', '')
        exact_matches = [
            manifest for manifest in matches if manifest.source_kind == source_kind
        ]
        if len(exact_matches) == 1:
            return exact_matches[0]
        if len(exact_matches) > 1:
            print(
                "[!] OpenGraph collector manifests: multiple manifests share "
                f"source_kind {source_kind!r}; using first registered"
            )
            return exact_matches[0]
        return matches[0]

    def _manifest_matches_node_kind_sets(
        self,
        manifest: CollectorManifest,
        node_kind_sets: List[Set[str]],
    ) -> bool:
        if not node_kind_sets:
            return False
        principal_kinds = set(manifest.principal_kinds)
        permitted_kinds = set(manifest.owned_kinds) | {'Base'}
        return (
            all(kinds.issubset(permitted_kinds) for kinds in node_kind_sets)
            and any(kinds & principal_kinds for kinds in node_kind_sets)
        )

    def _has_opengraph_sentinel_without_graph(self, data: dict) -> bool:
        metadata = data.get('metadata')
        if isinstance(metadata, dict) and 'source_kind' in metadata:
            return True
        schema = data.get('$schema')
        if not isinstance(schema, str):
            return False
        schema = schema.lower()
        return 'opengraph' in schema or 'open-graph' in schema

    def _filter_companion_properties(
        self,
        data: dict,
        manifest: CollectorManifest,
    ) -> Optional[dict]:
        # Strip collector-owned overlap props so companion files can only add
        # manifest-allowed additive fields, never clobber baseline data.
        graph = data.get('graph', {})
        nodes = graph.get('nodes', [])
        edges = graph.get('edges', [])
        out_nodes: List[dict] = []
        permitted_kinds = set(manifest.owned_kinds) | {'Base'}

        for node in nodes:
            if not set(node.get('kinds', [])).issubset(permitted_kinds):
                out_nodes.append(node)
                continue
            props = node.get('properties', {})
            kept = {
                key: value
                for key, value in props.items()
                if (
                    key in manifest.allowed_companion_properties
                    or any(
                        key.startswith(prefix)
                        for prefix in manifest.companion_property_prefixes
                    )
                )
            }
            if not kept and not edges:
                continue
            out_nodes.append({**node, 'properties': kept})

        if not out_nodes and not edges:
            return None

        data['graph']['nodes'] = out_nodes
        return data

    def _upload_json_files(self, entries: List[JsonEntry], *, validate_raw: bool = True) -> None:
        # SharpHound goes through CE so its native schema and post-processing
        # remain authoritative. OpenGraph companion/custom collector files are
        # loaded directly below; repeated CE analysis passes can OOM small
        # local stacks and custom-kind uploads can stall with empty statuses.
        if validate_raw:
            self._validate_opengraph_entries(entries)
        headers = {
            "User-Agent": "bh-automation",
            "Authorization": f"Bearer {self.jwt}",
            "Content-Type": "application/json",
        }

        sharphound_payloads: List[Tuple[str, object]] = []
        opengraph_payloads: List[OpenGraphPayload] = []
        for path, category, data in entries:
            if category == 'sharphound':
                sharphound_payloads.append((path.name, path))
            elif category == 'seed':
                print(f"[*] Skipping OpenGraph seed file: {path.name}")
            elif category == 'ad_companion' and data is not None:
                manifest = self._select_collector_manifest(data)
                if manifest is None:
                    raise ValueError(
                        f"OpenGraph {path.name}: companion collector manifest not found"
                    )
                body = self._filter_companion_properties(data, manifest)
                if body is not None:
                    opengraph_payloads.append((path.name, body, 'ad_companion'))
            elif category == 'opengraph' and data is not None:
                opengraph_payloads.append((path.name, data, 'opengraph'))

        # Filtering can remove AD companion nodes, so validate the exact direct
        # import payloads as well as the raw entries above.
        self._validate_opengraph_payloads(opengraph_payloads)

        if sharphound_payloads:
            upload_id = self._start_upload_batch(headers)
            for name, body in sharphound_payloads:
                self._upload_single_file(name, body, upload_id, headers)
            self._complete_upload_batch(upload_id, headers)
            self._wait_for_ingestion(upload_id, headers)

        stub_labels_used = self._import_opengraph_files_directly(
            opengraph_payloads,
            validate=False,
        )
        for label in sorted(stub_labels_used):
            self._merge_orphan_stubs(label)

        self._dedupe_mssql_servers()
        self._canonicalize_mssql_linked_server_edges()

        # Evaluate contracts after orphan-stub merge so future requirement
        # shapes see the final post-import graph state rather than a temporary
        # collector-stub layout.
        if opengraph_payloads:
            prime_from_checks()
            for warning in evaluate_opengraph_requirements(
                self.connection,
                opengraph_payloads,
            ):
                self._print_opengraph_requirement_warning(warning)

    def _import_opengraph_files_directly(
        self,
        payloads: List[OpenGraphPayload],
        *,
        validate: bool = True,
    ) -> Set[str]:
        # Keep this guard for direct callers and tests that bypass
        # _upload_json_files; it prevents partial Cypher writes.
        if validate:
            self._validate_opengraph_payloads(payloads)
        stub_labels_used: Set[str] = set()
        for name, body, merge_mode in payloads:
            data = body
            graph = data.get('graph', {})
            companion_manifest = (
                self._select_collector_manifest(data)
                if merge_mode == 'ad_companion'
                else None
            )
            if merge_mode == 'ad_companion' and companion_manifest is None:
                raise ValueError(
                    f"OpenGraph {name}: companion collector manifest not found"
                )
            endpoint_labels: Dict[str, str] = {}
            dropped_property_keys: Set[str] = set()
            skipped_ad_companion_nodes = 0
            missing_ad_principal_ids: Set[str] = set()
            stub_label = (
                self._stub_label_for_source_kind(data)
                if merge_mode == 'opengraph'
                else None
            )
            for node in graph.get('nodes', []):
                primary_label = self._import_opengraph_node(
                    node,
                    name,
                    merge_mode,
                    dropped_property_keys=dropped_property_keys,
                    missing_ad_principal_ids=missing_ad_principal_ids,
                    companion_manifest=companion_manifest,
                )
                if primary_label is None:
                    if merge_mode == 'ad_companion':
                        skipped_ad_companion_nodes += 1
                    continue
                endpoint_labels[str(node.get('id'))] = primary_label
            for edge in graph.get('edges', []):
                created_stub = self._import_opengraph_edge(
                    edge,
                    stub_label,
                    name,
                    create_stubs=(merge_mode == 'opengraph'),
                    endpoint_labels=endpoint_labels,
                    dropped_property_keys=dropped_property_keys,
                )
                if created_stub and stub_label:
                    stub_labels_used.add(stub_label)
            if dropped_property_keys:
                keys = ', '.join(sorted(dropped_property_keys))
                print(f"[!] OpenGraph {name}: dropped unsupported Neo4j properties: {keys}")
            if skipped_ad_companion_nodes:
                print(
                    f"[*] AD companion {name}: skipped "
                    f"{skipped_ad_companion_nodes} node(s) with no specific AD label"
                )
            if missing_ad_principal_ids:
                examples = ', '.join(
                    sorted(str(value) for value in missing_ad_principal_ids)[:3]
                )
                if len(missing_ad_principal_ids) > 3:
                    examples = f"{examples}, +{len(missing_ad_principal_ids) - 3} more"
                print(
                    f"[*] AD companion {name}: skipped "
                    f"{len(missing_ad_principal_ids)} node(s) whose SharpHound "
                    f"principal was not found. Examples: {examples}"
                )
        return stub_labels_used

    def _print_opengraph_requirement_warning(
        self,
        warning,
    ) -> None:
        example_text = ', '.join(warning.example_names)
        if warning.missing_count > len(warning.example_names):
            suffix = f"+{warning.missing_count - len(warning.example_names)} more"
            example_text = f"{example_text}, {suffix}" if example_text else suffix
        used_by = (
            f" Used by: {', '.join(warning.used_by)}."
            if warning.used_by
            else ""
        )
        print(
            f"[!] OpenGraph {warning.requirement_name}: import succeeded, but "
            f"{warning.missing_count} imported {warning.subject_label} node(s) "
            "are missing a required OpenGraph relationship. "
            f"{warning.warning} Findings that require this relationship for the "
            "listed nodes may be missed; other nodes that satisfy it can still "
            "produce findings. "
            f"Examples: {example_text}.{used_by}"
        )

    def _validate_opengraph_entries(self, entries: List[JsonEntry]) -> None:
        payloads: List[OpenGraphPayload] = [
            (path.name, data, category)
            for path, category, data in entries
            if category in {'opengraph', 'ad_companion', 'seed'} and data is not None
        ]
        self._validate_opengraph_payloads(payloads)

    def _validate_opengraph_payloads(self, payloads: List[OpenGraphPayload]) -> None:
        for name, body, merge_mode in payloads:
            self._validate_opengraph_payload(name, body, merge_mode)

    def _validate_opengraph_payload(
        self,
        source_name: str,
        data: dict,
        merge_mode: str,
    ) -> None:
        if 'graph' not in data:
            raise ValueError(f"OpenGraph {source_name}: graph must be an object")
        graph = data.get('graph')
        if not isinstance(graph, dict):
            raise ValueError(f"OpenGraph {source_name}: graph must be an object")
        nodes = graph.get('nodes', [])
        edges = graph.get('edges', [])
        if not isinstance(nodes, list):
            raise ValueError(f"OpenGraph {source_name}: graph.nodes must be a list")
        if not isinstance(edges, list):
            raise ValueError(f"OpenGraph {source_name}: graph.edges must be a list")

        metadata = data.get('metadata', {})
        if not isinstance(metadata, dict):
            raise ValueError(f"OpenGraph {source_name}: metadata must be an object")
        source_kind = self._validated_source_kind(metadata, source_name)

        if merge_mode == 'opengraph' and source_kind in reserved_labels():
            raise ValueError(
                f"OpenGraph {source_name}: metadata.source_kind "
                f"{source_kind!r} is reserved for SharpHound AD nodes"
            )

        skipped_empty_id: List[int] = []
        for index, node in enumerate(nodes):
            if not isinstance(node, dict):
                raise ValueError(
                    f"OpenGraph {source_name}: node {index} must be an object"
                )
            context_id = node.get('id', f"index {index}")
            if 'kinds' not in node or node.get('kinds') == []:
                labels = ['Base']
            else:
                labels = node.get('kinds')
            if not isinstance(labels, list):
                raise ValueError(
                    f"OpenGraph {source_name}: node {context_id!r} kinds must be a list"
                )
            properties = node.get('properties', {})
            if 'properties' in node and not isinstance(properties, dict):
                raise ValueError(
                    f"OpenGraph {source_name}: node {context_id!r} "
                    "properties must be an object"
                )
            for label in labels:
                self._safe_opengraph_identifier(
                    label,
                    'node label',
                    f"OpenGraph {source_name}: node {context_id!r} label",
                )
            if not node.get('id'):
                skipped_empty_id.append(index)

        if skipped_empty_id:
            dns_to_ids: Dict[str, Set[str]] = {}
            skipped_empty_id_set = set(skipped_empty_id)
            for i, n in enumerate(nodes):
                if i in skipped_empty_id_set:
                    continue
                nid = n.get('id', '')
                dns = (n.get('properties') or {}).get('DNSHostName', '')
                if nid and dns:
                    dns_to_ids.setdefault(str(dns).lower(), set()).add(str(nid))

            ambiguous_dns = {
                dns for dns, node_ids in dns_to_ids.items()
                if len(node_ids) > 1
            }
            dns_to_id = {
                dns: next(iter(node_ids))
                for dns, node_ids in dns_to_ids.items()
                if dns not in ambiguous_dns
            }

            resolved = 0
            ambiguous = 0
            still_empty: List[int] = []
            for i in skipped_empty_id:
                dns = (nodes[i].get('properties') or {}).get('DNSHostName', '')
                dns_key = str(dns).lower() if dns else ''
                if dns_key in ambiguous_dns:
                    ambiguous += 1
                    still_empty.append(i)
                    continue
                matched_id = dns_to_id.get(dns_key) if dns_key else None
                if matched_id:
                    nodes[i]['id'] = matched_id
                    resolved += 1
                else:
                    still_empty.append(i)

            if resolved:
                self._warn_import(
                    "opengraph_empty_id_resolved",
                    f"OpenGraph {source_name}: resolved {resolved} empty-id node(s) via DNSHostName"
                )
            if ambiguous:
                self._warn_import(
                    "opengraph_empty_id_ambiguous_dns",
                    f"OpenGraph {source_name}: skipped {ambiguous} empty-id node(s) with ambiguous DNSHostName"
                )
            if still_empty:
                skip_set = set(still_empty)
                graph['nodes'] = [n for i, n in enumerate(nodes) if i not in skip_set]
                self._warn_import(
                    "opengraph_empty_id_skipped",
                    f"OpenGraph {source_name}: skipped {len(still_empty)} node(s) with empty id"
                )

        for index, edge in enumerate(edges):
            if not isinstance(edge, dict):
                raise ValueError(
                    f"OpenGraph {source_name}: edge {index} must be an object"
                )
            self._validate_opengraph_endpoint(
                source_name,
                index,
                'start',
                edge.get('start'),
            )
            self._validate_opengraph_endpoint(
                source_name,
                index,
                'end',
                edge.get('end'),
            )
            self._safe_opengraph_identifier(
                edge.get('kind'),
                'relationship type',
                f"OpenGraph {source_name}: edge {index} kind",
            )
            properties = edge.get('properties', {})
            if 'properties' in edge and not isinstance(properties, dict):
                raise ValueError(
                    f"OpenGraph {source_name}: edge {index} "
                    "properties must be an object"
                )

    def _validated_source_kind(self, metadata: dict, source_name: str) -> str:
        source_kind = metadata.get('source_kind', '')
        if 'source_kind' in metadata and not isinstance(source_kind, str):
            raise ValueError(
                f"OpenGraph {source_name}: metadata.source_kind must be a string"
            )
        if not source_kind or not source_kind.strip():
            return ''
        return self._safe_opengraph_identifier(
            source_kind,
            'source_kind',
            f"OpenGraph {source_name}: metadata.source_kind",
        )

    def _validate_opengraph_endpoint(
        self,
        source_name: str,
        edge_index: int,
        side: str,
        endpoint: object,
    ) -> None:
        context = f"OpenGraph {source_name}: edge {edge_index} {side}"
        if not isinstance(endpoint, dict):
            raise ValueError(f"{context} must be an object")

        match_by = endpoint.get('match_by', 'id')
        if match_by not in {'id', 'name', 'property'}:
            raise ValueError(
                f"{context}.match_by must be one of 'id', 'name', or 'property'"
            )
        if 'kind' in endpoint:
            self._safe_opengraph_identifier(
                endpoint.get('kind'),
                'endpoint kind',
                f"{context}.kind",
            )

        value = endpoint.get('value')
        property_matchers = endpoint.get('property_matchers')
        if match_by in {'id', 'name'}:
            if not isinstance(value, str) or not value:
                raise ValueError(
                    f"{context}.value is required when match_by is {match_by!r}"
                )
            if property_matchers is not None:
                raise ValueError(
                    f"{context}.property_matchers is only supported with "
                    "match_by 'property'"
                )
            return

        if 'value' in endpoint:
            raise ValueError(
                f"{context}.value is not supported when match_by is 'property'"
            )
        self._validate_opengraph_property_matchers(context, property_matchers)

    def _validate_opengraph_property_matchers(
        self,
        context: str,
        property_matchers: object,
    ) -> None:
        if not isinstance(property_matchers, list) or not property_matchers:
            raise ValueError(
                f"{context}.property_matchers must be a non-empty list"
            )
        for index, matcher in enumerate(property_matchers):
            matcher_context = f"{context}.property_matchers[{index}]"
            if not isinstance(matcher, dict):
                raise ValueError(f"{matcher_context} must be an object")
            key = matcher.get('key')
            if not isinstance(key, str) or not key:
                raise ValueError(f"{matcher_context}.key must be a non-empty string")
            operator = matcher.get('operator', 'equals')
            if operator != 'equals':
                raise ValueError(f"{matcher_context}.operator must be 'equals'")
            if 'value' not in matcher or not isinstance(
                matcher.get('value'),
                _NEO4J_PROPERTY_SCALARS,
            ):
                raise ValueError(
                    f"{matcher_context}.value must be a string, number, or boolean"
                )

    def _safe_opengraph_identifier(self, value: str, kind: str, context: str) -> str:
        try:
            return safe_cypher_identifier(value, kind)
        except ValueError as exc:
            raise ValueError(f"{context} has unsupported identifier {value!r}") from exc

    def _warn_import(self, source: str, message: str) -> None:
        print(f"[!] {message}")
        if self._diagnostics:
            self._diagnostics.record_warning(f"import:{source}", message)

    def _stub_label_for_source_kind(self, data: dict) -> str:
        source_kind = data.get('metadata', {}).get('source_kind', '')
        if source_kind and source_kind.strip():
            label = safe_cypher_identifier(source_kind, 'source_kind')
            return label
        return 'OpenGraph_Stub'

    def _unique_safe_labels(self, labels: List[str], kind: str) -> List[str]:
        seen = set()
        safe_labels = []
        for label in labels:
            safe_label = safe_cypher_identifier(label, kind)
            if safe_label not in seen:
                safe_labels.append(safe_label)
                seen.add(safe_label)
        return safe_labels

    def _primary_opengraph_label(self, labels: List[str]) -> str:
        return next((label for label in labels if label != 'Base'), 'OpenGraph_Stub')

    def _primary_companion_label(
        self,
        labels: List[str],
        manifest: CollectorManifest,
    ) -> Optional[str]:
        principal_kinds = set(manifest.principal_kinds)
        return next((label for label in labels if label in principal_kinds), None)

    def _import_opengraph_node(
        self,
        node: dict,
        source_name: str,
        merge_mode: str,
        *,
        dropped_property_keys: Optional[Set[str]] = None,
        missing_ad_principal_ids: Optional[Set[str]] = None,
        companion_manifest: Optional[CollectorManifest] = None,
    ) -> Optional[str]:
        object_id = node.get('id')
        if not object_id:
            raise Exception(f"OpenGraph node missing id in {source_name}")

        raw_labels = node.get('kinds') if 'kinds' in node else ['Base']
        if raw_labels == []:
            raw_labels = ['Base']
        if not isinstance(raw_labels, list):
            raise ValueError(
                f"OpenGraph {source_name}: node {object_id!r} kinds must be a list"
            )
        labels = self._unique_safe_labels(raw_labels, 'node label')
        properties = _normalise_neo4j_properties(
            node.get('properties', {}),
            dropped_property_keys,
        )
        object_id = str(object_id)
        properties['objectid'] = object_id

        if merge_mode == 'ad_companion':
            if companion_manifest is None:
                raise ValueError(
                    f"OpenGraph {source_name}: companion collector manifest not found"
                )
            primary_label = self._primary_companion_label(labels, companion_manifest)
            if primary_label is None:
                return None
            result = self.connection.query(
                f"""
                MATCH (n:`{primary_label}` {{objectid: $objectid}})
                SET n += $properties
                RETURN count(n) AS matched
                """,
                parameters={'objectid': object_id, 'properties': properties},
            )
            matched = int(result[0].get('matched') or 0) if result else 0
            if not matched and missing_ad_principal_ids is not None:
                missing_ad_principal_ids.add(object_id)
            return primary_label

        if merge_mode != 'opengraph':
            raise Exception(f"Unsupported OpenGraph merge mode {merge_mode!r} in {source_name}")

        primary_label = self._primary_opengraph_label(labels)
        extra_labels_clause = ''.join(
            f":`{label}`"
            for label in labels
            if label != primary_label and label != 'Base'
        )
        set_extra_labels = f"SET n{extra_labels_clause}" if extra_labels_clause else ""
        self.connection.query(
            f"""
            MERGE (n:`{primary_label}` {{objectid: $objectid}})
            SET n += $properties
            {set_extra_labels}
            """,
            parameters={'objectid': object_id, 'properties': properties},
        )
        return primary_label

    def _ensure_opengraph_endpoint(self, object_id: str, stub_label: str) -> bool:
        result = self.connection.query(
            "MATCH (n {objectid: $objectid}) RETURN count(n) AS c",
            parameters={'objectid': object_id},
        )
        if result and result[0]['c'] > 0:
            return False

        label = safe_cypher_identifier(stub_label, 'stub label')
        self.connection.query(
            f"""
            MERGE (n:`{label}` {{objectid: $objectid}})
            SET n.name = coalesce(n.name, $objectid)
            """,
            parameters={'objectid': object_id},
        )
        return True

    def _normalise_endpoint_property_matchers(
        self,
        property_matchers: List[dict],
    ) -> Tuple[dict, ...]:
        normalised = []
        for matcher in property_matchers:
            normalised.append(
                {
                    'key': matcher['key'],
                    'operator': matcher.get('operator', 'equals'),
                    'value': matcher['value'],
                }
            )
        return tuple(normalised)

    def _endpoint_reference(
        self,
        edge: dict,
        side: str,
        endpoint_labels: Dict[str, str],
    ) -> EndpointReference:
        endpoint = edge.get(side) or {}
        if not isinstance(endpoint, dict):
            raise ValueError(f"OpenGraph edge {side} endpoint must be an object")

        match_by = endpoint.get('match_by', 'id')
        kind = endpoint.get('kind')
        label = (
            safe_cypher_identifier(kind, 'endpoint kind')
            if kind is not None
            else None
        )
        if match_by in {'id', 'name'}:
            value = endpoint.get('value')
            if not isinstance(value, str) or not value:
                raise ValueError(f"OpenGraph edge {side}.value is required")
            if match_by == 'id' and label is None:
                payload_label = endpoint_labels.get(value)
                if payload_label:
                    label = safe_cypher_identifier(payload_label, 'endpoint label')
            return EndpointReference(match_by=match_by, value=value, label=label)

        if match_by == 'property':
            property_matchers = endpoint.get('property_matchers')
            if not isinstance(property_matchers, list) or not property_matchers:
                raise ValueError(
                    f"OpenGraph edge {side}.property_matchers must be a non-empty list"
                )
            return EndpointReference(
                match_by=match_by,
                property_matchers=self._normalise_endpoint_property_matchers(
                    property_matchers
                ),
                label=label,
            )

        raise ValueError(f"OpenGraph edge {side}.match_by is unsupported")

    def _maybe_create_id_endpoint_stub(
        self,
        endpoint: EndpointReference,
        stub_label: str,
        endpoint_labels: Dict[str, str],
    ) -> bool:
        if endpoint.match_by != 'id' or endpoint.label is not None:
            return False
        object_id = endpoint.value
        if not object_id or object_id in endpoint_labels:
            return False
        created = self._ensure_opengraph_endpoint(object_id, stub_label)
        if created:
            endpoint_labels[object_id] = stub_label
            endpoint.label = safe_cypher_identifier(stub_label, 'endpoint label')
        return created

    def _import_opengraph_edge(
        self,
        edge: dict,
        stub_label: Optional[str],
        source_name: str,
        *,
        create_stubs: bool,
        endpoint_labels: Dict[str, str],
        dropped_property_keys: Optional[Set[str]] = None,
    ) -> bool:
        start_endpoint = self._endpoint_reference(edge, 'start', endpoint_labels)
        end_endpoint = self._endpoint_reference(edge, 'end', endpoint_labels)
        created_stub = False
        if create_stubs:
            if not stub_label:
                raise Exception(f"OpenGraph edge needs a stub label in {source_name}")
            created_stub = (
                self._maybe_create_id_endpoint_stub(
                    start_endpoint,
                    stub_label,
                    endpoint_labels,
                )
                or created_stub
            )
            created_stub = (
                self._maybe_create_id_endpoint_stub(
                    end_endpoint,
                    stub_label,
                    endpoint_labels,
                )
                or created_stub
            )

        rel_type = safe_cypher_identifier(edge.get('kind'), 'relationship type')
        properties = _normalise_neo4j_properties(
            edge.get('properties', {}),
            dropped_property_keys,
        )
        query, endpoint_parameters = self._opengraph_edge_query(
            rel_type,
            start_endpoint,
            end_endpoint,
        )
        self.connection.query(
            query,
            parameters={
                **endpoint_parameters,
                'properties': properties,
            },
        )
        return created_stub

    def _opengraph_edge_query(
        self,
        rel_type: str,
        start_endpoint: EndpointReference,
        end_endpoint: EndpointReference,
    ) -> Tuple[str, dict]:
        start_match, start_params = self._endpoint_match_clause(
            'start',
            start_endpoint,
        )
        end_match, end_params = self._endpoint_match_clause(
            'end',
            end_endpoint,
        )
        return (
            f"""
            {start_match}
            WITH collect(start)[0] AS start
            WHERE start IS NOT NULL
            {end_match}
            WITH start, collect(end)[0] AS end
            WHERE end IS NOT NULL
            MERGE (start)-[r:`{rel_type}`]->(end)
            SET r += $properties
            """,
            {**start_params, **end_params},
        )

    def _endpoint_match_clause(
        self,
        variable: str,
        endpoint: EndpointReference,
    ) -> Tuple[str, dict]:
        label = f":`{endpoint.label}`" if endpoint.label else ""
        if endpoint.match_by == 'id':
            return (
                f"MATCH ({variable}{label} {{objectid: ${variable}_id}})",
                {f"{variable}_id": endpoint.value},
            )
        if endpoint.match_by == 'name':
            return (
                f"MATCH ({variable}{label})\n"
                f"            WHERE {variable}.name = ${variable}_name",
                {f"{variable}_name": endpoint.value},
            )
        if endpoint.match_by == 'property':
            return (
                f"MATCH ({variable}{label})\n"
                f"            WHERE all(matcher IN ${variable}_property_matchers "
                f"WHERE {variable}[matcher.key] = matcher.value)",
                {f"{variable}_property_matchers": list(endpoint.property_matchers)},
            )
        raise ValueError(
            f"Unsupported OpenGraph endpoint match strategy: {endpoint.match_by!r}"
        )

    def _dedupe_mssql_servers(self) -> int:
        return dedupe_mssql_servers(self.connection)

    def _canonicalize_mssql_linked_server_edges(self) -> int:
        return canonicalize_mssql_linked_server_edges(self.connection)

    def _merge_orphan_stubs(self, label: str) -> None:
        # don't copy the collector label onto the AD node — account_analysis would mis-classify it as a stub
        label = safe_cypher_identifier(label, 'orphan stub label')
        if label in reserved_labels():
            raise ValueError(f"Refusing orphan merge for broad label: {label!r}")
        pairs = self.connection.query(f"""
            MATCH (stub:`{label}`) WHERE size(labels(stub)) = 1
            WITH stub
            MATCH (real) WHERE real.objectid = stub.objectid
              AND (real:User OR real:Computer OR real:Group)
            RETURN count(*) as c
        """)
        if not pairs or not pairs[0].get('c'):
            return

        rel_types = self.connection.query(f"""
            MATCH (stub:`{label}`)-[r]-()
            WHERE size(labels(stub)) = 1
            RETURN DISTINCT type(r) as rtype
        """)
        for rt in (rel_types or []):
            rtype = safe_cypher_identifier(rt['rtype'], 'relationship type')
            self.connection.query(f"""
                MATCH (stub:`{label}`)-[old:`{rtype}`]->(target)
                WHERE size(labels(stub)) = 1
                WITH stub, old, target
                MATCH (real) WHERE real.objectid = stub.objectid
                  AND (real:User OR real:Computer OR real:Group)
                  AND target <> real
                MERGE (real)-[new:`{rtype}`]->(target)
                WITH old, new, properties(old) AS old_props, properties(new) AS existing_props
                SET new += old_props SET new += existing_props
                DELETE old
            """)
            self.connection.query(f"""
                MATCH (source)-[old:`{rtype}`]->(stub:`{label}`)
                WHERE size(labels(stub)) = 1
                WITH source, old, stub
                MATCH (real) WHERE real.objectid = stub.objectid
                  AND (real:User OR real:Computer OR real:Group)
                  AND source <> real
                MERGE (source)-[new:`{rtype}`]->(real)
                WITH old, new, properties(old) AS old_props, properties(new) AS existing_props
                SET new += old_props SET new += existing_props
                DELETE old
            """)

        self.connection.query(f"""
            MATCH (stub:`{label}`)
            WHERE size(labels(stub)) = 1
            WITH stub
            MATCH (real) WHERE real.objectid = stub.objectid
              AND (real:User OR real:Computer OR real:Group)
            DETACH DELETE stub
        """)

    def _start_upload_batch(self, headers: Dict[str, str]) -> str:
        url = f"{self.base_url}/api/v2/file-upload/start"
        response = requests.post(
            url,
            headers=headers,
            timeout=self.request_timeout_seconds,
        )

        if response.status_code not in (200, 201):
            raise Exception(f"Failed to start upload batch: {response.status_code}")

        return response.json()["data"]["id"]

    def _upload_single_file(self, name: str, body, upload_id: str, headers: Dict[str, str]) -> None:
        if isinstance(body, Path):
            with open(body, "r", encoding="utf-8-sig") as f:
                body = f.read().encode("utf-8")

        url = f"{self.base_url}/api/v2/file-upload/{upload_id}"
        response = requests.post(
            url,
            headers=headers,
            data=body,
            timeout=self.request_timeout_seconds,
        )

        if response.status_code not in (200, 202):
            raise Exception(f"Failed to upload {name}: HTTP {response.status_code}")

    def _complete_upload_batch(self, upload_id: str, headers: Dict[str, str]) -> None:
        url = f"{self.base_url}/api/v2/file-upload/{upload_id}/end"
        response = requests.post(
            url,
            headers=headers,
            timeout=self.request_timeout_seconds,
        )

        if response.status_code != 200:
            raise Exception("Failed to complete upload batch")

    def _deduplicate_by_identity(self, entries: List[JsonEntry]) -> List[JsonEntry]:
        # Collector manifests own identity rules. The importer only suppresses
        # exact duplicate identities within the same manifest.
        by_identity: Dict[Tuple[str, str], JsonEntry] = {}
        dedupe_notes: List[str] = []
        passthrough: List[JsonEntry] = []

        for entry in entries:
            path, category, data = entry
            if category != 'opengraph' or not isinstance(data, dict):
                passthrough.append(entry)
                continue

            manifest = self._select_collector_manifest(data)
            identity = self._collector_identity(manifest, data)
            if not manifest or not identity:
                passthrough.append(entry)
                continue

            key = (manifest.source_kind, identity)
            if key in by_identity:
                dedupe_notes.append(
                    f"{path.name} replaced {by_identity[key][0].name} "
                    f"for {manifest.source_kind}:{identity}"
                )
            by_identity[key] = entry

        kept = [*passthrough, *by_identity.values()]
        if dedupe_notes:
            print(
                "[*] OpenGraph identity dedupe: skipped "
                f"{len(dedupe_notes)} duplicate collector file(s)"
            )
            for note in dedupe_notes[:3]:
                print(f"    - {note}")
            if len(dedupe_notes) > 3:
                print(f"    - +{len(dedupe_notes) - 3} more")
        return kept

    def _collector_identity(
        self,
        manifest: Optional[CollectorManifest],
        data: dict,
    ) -> Optional[str]:
        if manifest is None:
            return None
        if manifest.identity_fn is not None:
            return manifest.identity_fn(data)
        if not manifest.identity_properties:
            return None

        graph = data.get('graph', {})
        for node in graph.get('nodes', []):
            kinds = node.get('kinds', [])
            if not any(kind in manifest.principal_kinds for kind in kinds):
                continue
            properties = node.get('properties', {})
            values = [
                properties.get(property_name)
                for property_name in manifest.identity_properties
            ]
            if any(value in (None, '') for value in values):
                return None
            return '|'.join(str(value).lower() for value in values)
        return None

    # BH CE upload statuses that mean we should stop the import.
    # "Complete" and "Partially Completed" are handled inline because they
    # need different messaging (silent vs notice) — Partially Completed
    # means data ingested but post-analysis hit a non-fatal error, and the
    # stub-merge step can still recover from that.
    _ABORT_STATUSES = frozenset({"Failed", "Canceled", "Timed Out"})
    _INGESTION_TIMEOUT_SECONDS = 600
    _INGESTION_TIMEOUT_ENV = "ADPF_BH_INGESTION_TIMEOUT_SECONDS"
    _REQUEST_TIMEOUT_SECONDS = 60
    _REQUEST_TIMEOUT_ENV = "ADPF_BH_REQUEST_TIMEOUT_SECONDS"

    def _resolve_ingestion_timeout(self, timeout: Optional[int]) -> int:
        return self._resolve_int_timeout(
            timeout,
            self._INGESTION_TIMEOUT_ENV,
            self._INGESTION_TIMEOUT_SECONDS,
        )

    def _resolve_request_timeout(self, timeout: Optional[int]) -> int:
        return self._resolve_int_timeout(
            timeout,
            self._REQUEST_TIMEOUT_ENV,
            self._REQUEST_TIMEOUT_SECONDS,
        )

    @staticmethod
    def _resolve_int_timeout(timeout: Optional[int], env_var: str, default: int) -> int:
        raw_timeout = os.environ.get(env_var) if timeout is None else timeout
        if raw_timeout is None:
            raw_timeout = default
        try:
            resolved = int(raw_timeout)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"{env_var} must be a positive integer "
                "number of seconds"
            ) from exc
        if resolved <= 0:
            raise ValueError(
                f"{env_var} must be a positive integer "
                "number of seconds"
            )
        return resolved

    def _wait_for_ingestion(self, upload_id: str, headers: Dict[str, str]) -> None:
        # raises on failure so caller doesn't merge against a broken graph
        status_url = f"{self.base_url}/api/v2/file-upload?skip=0&limit=10&sort_by=-id"
        check_interval = 5
        started_at = time.monotonic()
        last_status = None

        while True:
            response = requests.get(
                status_url,
                headers=headers,
                timeout=self.request_timeout_seconds,
            )
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
                    last_status = latest_status
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

            elapsed = time.monotonic() - started_at
            if elapsed > self.ingestion_timeout_seconds:
                raise Exception(
                    f"Timed out after {int(elapsed)}s waiting for BH CE ingestion "
                    f"upload {upload_id}; configured timeout is "
                    f"{self.ingestion_timeout_seconds}s via "
                    f"{self._INGESTION_TIMEOUT_ENV}. BloodHound CE may have "
                    "accepted files for this batch before analysis completed; "
                    "ADPathfinder stopped before direct OpenGraph import and "
                    f"stub merge. Last observed status: {last_status}"
                )

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

            response = requests.post(
                url,
                headers=headers,
                json=data,
                timeout=self.request_timeout_seconds,
            )
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

        response = requests.put(
            url,
            headers=headers,
            json=data,
            timeout=self.request_timeout_seconds,
        )

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
