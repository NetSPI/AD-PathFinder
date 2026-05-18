from dataclasses import dataclass
from importlib import import_module
from typing import Callable, Literal, Optional, Sequence, Tuple

from .opengraph_identifiers import safe_cypher_identifier


IdentityFunction = Callable[[dict], Optional[str]]


def _tuple_of_strings(values: Sequence[str], field_name: str) -> Tuple[str, ...]:
    if isinstance(values, str):
        raise TypeError(f"{field_name} must be a sequence of strings")
    items = tuple(values or ())
    for item in items:
        if not isinstance(item, str) or not item:
            raise ValueError(f"{field_name} entries must be non-empty strings")
    return items


@dataclass(frozen=True)
class CollectorManifest:
    source_kind: str
    principal_kinds: Tuple[str, ...]
    owned_kinds: Tuple[str, ...] = ()
    reserved_labels: Tuple[str, ...] = ()
    merge_strategy: Literal["opengraph", "companion_additive"] = "opengraph"
    allowed_companion_properties: Tuple[str, ...] = ()
    companion_property_prefixes: Tuple[str, ...] = ()
    identity_properties: Tuple[str, ...] = ()
    identity_fn: Optional[IdentityFunction] = None

    def __post_init__(self) -> None:
        if not isinstance(self.source_kind, str) or not self.source_kind.strip():
            raise ValueError("CollectorManifest source_kind must be a non-empty string")
        if self.merge_strategy not in {"opengraph", "companion_additive"}:
            raise ValueError(
                f"Unsupported collector merge strategy: {self.merge_strategy!r}"
            )

        principal_kinds = _tuple_of_strings(self.principal_kinds, "principal_kinds")
        if not principal_kinds:
            raise ValueError("CollectorManifest principal_kinds must not be empty")
        owned_kinds = _tuple_of_strings(self.owned_kinds, "owned_kinds")
        if not owned_kinds:
            owned_kinds = principal_kinds
        if not set(principal_kinds).issubset(set(owned_kinds)):
            raise ValueError("CollectorManifest owned_kinds must include principal_kinds")
        reserved_labels = _tuple_of_strings(self.reserved_labels, "reserved_labels")
        allowed_properties = _tuple_of_strings(
            self.allowed_companion_properties,
            "allowed_companion_properties",
        )
        property_prefixes = _tuple_of_strings(
            self.companion_property_prefixes,
            "companion_property_prefixes",
        )
        identity_properties = _tuple_of_strings(
            self.identity_properties,
            "identity_properties",
        )

        if identity_properties and self.identity_fn is not None:
            raise ValueError("identity_properties and identity_fn are mutually exclusive")
        if self.identity_fn is not None and not callable(self.identity_fn):
            raise TypeError("identity_fn must be callable")

        for label in (*owned_kinds, *reserved_labels):
            safe_cypher_identifier(label, "node label")

        object.__setattr__(self, "principal_kinds", principal_kinds)
        object.__setattr__(self, "owned_kinds", owned_kinds)
        object.__setattr__(self, "reserved_labels", reserved_labels)
        object.__setattr__(self, "allowed_companion_properties", allowed_properties)
        object.__setattr__(self, "companion_property_prefixes", property_prefixes)
        object.__setattr__(self, "identity_properties", identity_properties)


_REGISTERED_COLLECTOR_MANIFESTS = []
_COLLECTORS_PRIMED = False


def register_collector_manifest(manifest: CollectorManifest) -> None:
    if not isinstance(manifest, CollectorManifest):
        raise TypeError("collector manifest must be a CollectorManifest")
    _REGISTERED_COLLECTOR_MANIFESTS.append(manifest)


def registered_manifests() -> Tuple[CollectorManifest, ...]:
    return tuple(_REGISTERED_COLLECTOR_MANIFESTS)


def prime_from_collectors() -> Tuple[CollectorManifest, ...]:
    global _COLLECTORS_PRIMED
    if _COLLECTORS_PRIMED:
        return registered_manifests()

    import_module("modules.collectors")
    _COLLECTORS_PRIMED = True
    return registered_manifests()
