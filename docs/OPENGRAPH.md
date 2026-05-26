# OpenGraph Plugin Data Contract

ADPathfinder treats OpenGraph plugin data as supplementary data. It must be
imported alongside SharpHound/BloodHound data, or into a database that already
contains that AD baseline. A standalone OpenGraph-only graph is not a supported
audit mode.

## ZIP Layout

An OpenGraph plugin ZIP contains one or more JSON files. JSON files may be at
the ZIP root or nested under plugin directories such as `PluginName/data/`.
Every JSON payload must have a top-level `graph` object:

```json
{
  "metadata": {
    "source_kind": "Jenkins_Base"
  },
  "graph": {
    "nodes": [],
    "edges": []
  }
}
```

If every JSON payload in every imported ZIP has a `graph` object, ADPathfinder
treats the import as supplementary-only and appends it to existing BloodHound
data. Mixed imports such as `SharpHound.zip MSSQLHound.zip` are treated as a
BloodHound data import because they can establish or refresh the AD baseline.

`metadata` may be omitted. If present, it must be a JSON object. When
`metadata.source_kind` is present, it must be a string. Empty or whitespace-only
values are treated as omitted; non-empty values must match the same safe
identifier rule as labels.

If BloodHound CE analysis takes longer than the default 600 seconds, set
`ADPF_BH_INGESTION_TIMEOUT_SECONDS` to a positive integer number of seconds.

## Nodes

Node shape:

```json
{
  "id": "jenkins-1",
  "kinds": ["Base", "Jenkins_Server"],
  "properties": {
    "name": "ci.example.local",
    "url": "https://ci.example.local"
  }
}
```

Rules:

- `id` is required and becomes the Neo4j `objectid`.
- `kinds` are Neo4j labels. The first non-`Base` kind is used as the primary
  merge label. `Base` is treated as a collector compatibility marker and is not
  added as an extra label on generic OpenGraph nodes. If a generic OpenGraph
  node has no non-`Base` kind, it is merged as `OpenGraph_Stub` so it cannot
  collide with SharpHound AD nodes.
- Label names must match `[A-Za-z_][A-Za-z0-9_]*`. Hyphens, spaces, leading
  digits, and punctuation are rejected.
- `properties` is optional and defaults to `{}`. If present, it must be a JSON
  object.
- Node property values may be strings, integers, floats, booleans, or
  homogeneous lists of those scalar types. `null`, dictionaries, mixed-type
  lists, and non-string property keys are dropped. The importer prints one
  warning per file listing dropped keys.

## Edges

Edge shape:

```json
{
  "kind": "Jenkins_AdminTo",
  "start": {"match_by": "id", "value": "S-1-5-21-example-1105"},
  "end": {"match_by": "id", "value": "jenkins-1"},
  "properties": {
    "source": "collector-name"
  }
}
```

Rules:

- `kind` becomes the Neo4j relationship type and must match the same identifier
  rule as labels.
- `start` and `end` support the BloodHound OpenGraph endpoint strategies:
  `match_by: "id"` (the default), deprecated `match_by: "name"`, and
  `match_by: "property"`.
- `match_by: "id"` and `match_by: "name"` require `value`.
  `match_by: "property"` requires a non-empty `property_matchers` array and
  forbids `value`.
- Property matchers currently support only `operator: "equals"`. The operator
  may be omitted and defaults to `equals`. Matcher values must be strings,
  numbers, or booleans.
- Endpoint `kind` is optional. When present, it constrains the node match and
  must match the same safe identifier rule as labels.
- When an `id` endpoint node is declared in the same OpenGraph payload and no
  endpoint `kind` is supplied, the importer matches it by
  `(primary_label, objectid)`.
- When an unconstrained `id` endpoint is not declared in the payload, the
  importer matches an existing node with the same `objectid`. If none exists,
  generic OpenGraph mode creates an endpoint stub.
- `properties` is optional and defaults to `{}`. If present, it must be a JSON
  object. Edge property values follow the same supported-value rules as node
  properties.

Name endpoint example:

```json
{
  "kind": "Jenkins_AdminTo",
  "start": {
    "match_by": "name",
    "kind": "User",
    "value": "ALICE@EXAMPLE.LOCAL"
  },
  "end": {"value": "jenkins-1"}
}
```

Property endpoint example:

```json
{
  "kind": "Jenkins_Owns",
  "start": {
    "match_by": "property",
    "kind": "Jenkins_User",
    "property_matchers": [
      {"key": "email", "operator": "equals", "value": "dev@example.local"}
    ]
  },
  "end": {"value": "jenkins-1"}
}
```

## Stubs

Endpoint stubs use `metadata.source_kind` as their label when it is present. If
`source_kind` is missing, empty, or whitespace-only, the importer uses
`OpenGraph_Stub`. Invalid non-empty `source_kind` values are rejected before any
OpenGraph writes are attempted.

Stubs are created only for `match_by: "id"` endpoints that do not supply an
endpoint `kind`. A typed endpoint that does not resolve is left unmatched rather
than fabricated as that type.

Do not use broad AD labels such as `Base`, `User`, `Computer`, or `Group` as a
plugin source kind. Those labels are owned by the SharpHound baseline.

## Semantic Relationships

Valid OpenGraph data is allowed to import even when optional relationships used
by specific ADPathfinder checks are missing. The importer prints a warning when
it can identify that imported nodes lack a known semantic relationship; checks
that depend on that relationship may then return no findings.

Relationship derivation must come from explicit collector data. Collectors
should emit the relationship directly when they can prove it, or derive it from
explicit metadata such as an object ID or SID mapping. ADPathfinder does not
infer platform relationships from hostnames.

Current optional semantic relationships:

| Relationship | Pattern | Consumed by checks | If absent |
| --- | --- | --- | --- |
| `MSSQL_HostFor` | `Computer-[:MSSQL_HostFor]->MSSQL_Server` | `mssql_linked_servers`, `mssql_impersonation`, `mssql_ntlm_relay`, `sccm_takeover1`, `sccm_takeover2` | Imported MSSQL data remains valid, but findings tied to unmapped `MSSQL_Server` nodes may be missed. Mapped nodes can still produce findings. |

Standalone MSSQLHound sample output in `sample_data/MSSQLHound.zip` emits
`MSSQL_Server` nodes and MSSQL internal relationships, but it does not emit real
`MSSQL_HostFor` edges. ConfigManBearPig sample output emits `MSSQL_HostFor` in
`sccm.json` when it can resolve SQL servers to AD computers.

Mapped MSSQL example:

```json
{
  "metadata": {"source_kind": "MSSQL_Base"},
  "graph": {
    "nodes": [
      {
        "id": "sql01.example.local:1433",
        "kinds": ["Base", "MSSQL_Server"],
        "properties": {"name": "sql01.example.local:1433"}
      }
    ],
    "edges": [
      {
        "kind": "MSSQL_HostFor",
        "start": {"value": "S-1-5-21-example-1101"},
        "end": {"value": "sql01.example.local:1433"}
      }
    ]
  }
}
```

In that example, `S-1-5-21-example-1101` must be the `objectid` of an existing
SharpHound `Computer` node. If that AD computer cannot be resolved, do not emit
`MSSQL_HostFor`.

Unmapped MSSQL example:

```json
{
  "metadata": {"source_kind": "MSSQL_Base"},
  "graph": {
    "nodes": [
      {
        "id": "sql01.example.local:1433",
        "kinds": ["Base", "MSSQL_Server"],
        "properties": {"name": "sql01.example.local:1433"}
      }
    ],
    "edges": []
  }
}
```

The unmapped form imports successfully, but ADPathfinder warns that the imported
`MSSQL_Server` node is missing the host-mapping relationship required by the
checks listed above.

This warning is scoped to the listed imported nodes. If another collector also
imports mapped `MSSQL_Server` nodes for the same logical hosts, the host-mapped
checks can still produce findings from those mapped nodes while ADPathfinder
warns about the unmapped duplicates.

## AD Companion Payloads

Files whose nodes are all AD kinds (`Base`, `User`, `Computer`, `Group`) are
handled as AD companion data. This mode enriches existing SharpHound principals
instead of creating replacement AD nodes.

For AD companion nodes:

- Only additive properties are kept: `SMBSigningRequired`, `collectionSource`,
  `disableLoopbackCheck`, `restrictReceivingNtlmTraffic`,
  `storedInSCCMSite`, and properties whose names start with `SCCM`.
- AD-overlap properties such as `name`, `description`, and `objectid` from the
  companion file are dropped.
- Nodes are matched by the specific AD label (`User`, `Computer`, or `Group`)
  and `objectid`. Missing SharpHound principals are not created.
- Companion files may still carry relationships between existing AD principals.

## Adding Plugin Support

Most OpenGraph plugins should be plug-and-play. If a plugin ZIP contains valid
OpenGraph JSON, ADPathfinder imports it through the generic node, edge, endpoint,
and stub handling described above. In that normal path, developers only add
checks that query the plugin's labels and relationships. No importer change and
no collector manifest are required.

Add check-owned `OPENGRAPH_REQUIREMENTS` when a check depends on plugin
relationships that may be absent from otherwise valid data. This keeps missing
semantic warnings close to the checks that need those semantics.

## Collector Manifests

Collector manifests in `modules/collectors/` are optional importer policy
adapters. Add one only when a plugin needs behavior beyond generic OpenGraph
upload, such as exact identity dedupe, companion enrichment of existing AD
principals, or reserved labels that must not become generic stubs. It should
still never require a collector-specific branch in `BloodhoundImporter.py`.

Manifest-owned fields:

- `source_kind`: collector identifier used for exact manifest tie-breaks.
- `principal_kinds`: node labels used as identity anchors for the collector.
- `owned_kinds`: full set of non-`Base` node labels a collector file may
  contain. If omitted, this defaults to `principal_kinds`. The importer treats
  `Base` as an implicit compatibility label for matching and companion
  filtering.
- `reserved_labels`: labels that cannot be used as generic stub labels.
- `merge_strategy`: `opengraph` for generic direct import or
  `companion_additive` for additive enrichment of existing principals.
- `allowed_companion_properties` and `companion_property_prefixes`: properties
  preserved during companion filtering.
- `identity_properties` or `identity_fn`: exact duplicate suppression for
  collector files.

SharpHound is represented as a companion-additive manifest for `User`,
`Computer`, and `Group` nodes. MSSQLHound is represented as an OpenGraph
manifest anchored on `MSSQL_Server`, with extra `owned_kinds` for normal
MSSQLHound login, role, user, and database nodes. It uses an `identity_fn`
because SQL identity can come from host, port, or instance fields. A simple
custom collector can stay declarative with
`identity_properties=("name",)`.

## Compatibility Policy

ADPathfinder follows the public BloodHound OpenGraph contract for graph shape,
safe relationship identifiers, endpoint `match_by` modes, and property matcher
semantics. The upstream docs are:

- https://bloodhound.specterops.io/opengraph/developer/schema
- https://bloodhound.specterops.io/opengraph/developer/graph-data

Intentional ADPathfinder differences:

- `metadata.source_kind` may be omitted. Empty or whitespace-only values are
  treated as omitted. Non-empty values must be safe identifiers because
  ADPathfinder uses them as fallback endpoint-stub labels.
- ADPathfinder does not append `source_kind` to every imported node.
- Missing or empty `node.kinds` falls back to `Base`; generic Base-only nodes
  are merged as `OpenGraph_Stub`.
- Unsupported Neo4j property values are dropped with a warning instead of
  failing the whole file.
- Endpoint stubs are ADPathfinder local recovery behavior, not a BloodHound
  uploader feature.

## Minimal Example

```json
{
  "metadata": {"source_kind": "Jenkins_Base"},
  "graph": {
    "nodes": [
      {
        "id": "jenkins-1",
        "kinds": ["Base", "Jenkins_Server"],
        "properties": {"name": "ci.example.local"}
      }
    ],
    "edges": [
      {
        "kind": "Jenkins_AdminTo",
        "start": {"value": "S-1-5-21-example-1105"},
        "end": {"value": "jenkins-1"},
        "properties": {}
      }
    ]
  }
}
```

Import it after SharpHound data exists:

```bash
adpathfinder --import JenkinsGraph.zip
```

Or import it with the baseline in one command:

```bash
adpathfinder --import SharpHound.zip JenkinsGraph.zip
```
