from dataclasses import dataclass, replace
from importlib import import_module
from typing import List, Optional, Sequence, Tuple

from .opengraph_identifiers import safe_cypher_identifier


@dataclass(frozen=True)
class RequiredRelationship:
    from_label: str
    relationship: str
    to_label: str
    direction: str = "incoming"

    def __post_init__(self):
        object.__setattr__(
            self,
            "from_label",
            safe_cypher_identifier(self.from_label, "node label"),
        )
        object.__setattr__(
            self,
            "relationship",
            safe_cypher_identifier(self.relationship, "relationship type"),
        )
        object.__setattr__(
            self,
            "to_label",
            safe_cypher_identifier(self.to_label, "node label"),
        )
        if self.direction not in {"incoming", "outgoing"}:
            raise ValueError(
                f"Unsupported OpenGraph requirement direction: {self.direction!r}"
            )


@dataclass(frozen=True)
class OpenGraphRequirement:
    name: str
    when_label: str
    required_relationship: RequiredRelationship
    warning: str
    used_by: Tuple[str, ...] = ()

    def __post_init__(self):
        object.__setattr__(
            self,
            "when_label",
            safe_cypher_identifier(self.when_label, "node label"),
        )
        if not isinstance(self.required_relationship, RequiredRelationship):
            raise TypeError("required_relationship must be a RequiredRelationship")
        relationship = self.required_relationship
        if (
            relationship.direction == "incoming"
            and relationship.to_label != self.when_label
        ):
            raise ValueError(
                "Incoming OpenGraph requirements must target the when_label"
            )
        if (
            relationship.direction == "outgoing"
            and relationship.from_label != self.when_label
        ):
            raise ValueError(
                "Outgoing OpenGraph requirements must start from the when_label"
            )


@dataclass(frozen=True)
class OpenGraphRequirementWarning:
    requirement_name: str
    subject_label: str
    warning: str
    missing_count: int
    example_names: Tuple[str, ...]
    used_by: Tuple[str, ...] = ()


def mssql_host_mapping_requirement(*used_by: str) -> OpenGraphRequirement:
    return OpenGraphRequirement(
        name="MSSQL host mapping",
        when_label="MSSQL_Server",
        required_relationship=RequiredRelationship(
            from_label="Computer",
            relationship="MSSQL_HostFor",
            to_label="MSSQL_Server",
            direction="incoming",
        ),
        used_by=tuple(used_by),
        warning=(
            "Collectors should emit this edge when they can resolve the SQL "
            "server to an AD computer: "
            "Computer-[:MSSQL_HostFor]->MSSQL_Server."
        ),
    )


BUILT_IN_OPENGRAPH_REQUIREMENTS: Tuple[OpenGraphRequirement, ...] = (
    mssql_host_mapping_requirement(
        "mssql_linked_servers",
        "mssql_impersonation",
        "mssql_ntlm_relay",
        "sccm_takeover1",
        "sccm_takeover2",
    ),
)


_REGISTERED_CHECK_REQUIREMENTS: List[OpenGraphRequirement] = []
_CHECK_REQUIREMENTS_PRIMED = False


def register_opengraph_requirements(
    requirements: Sequence[OpenGraphRequirement],
) -> None:
    for requirement in requirements:
        if not isinstance(requirement, OpenGraphRequirement):
            raise TypeError("OpenGraph check requirements must be OpenGraphRequirement")
        _REGISTERED_CHECK_REQUIREMENTS.append(requirement)


def registered_opengraph_requirements() -> Tuple[OpenGraphRequirement, ...]:
    return tuple(_REGISTERED_CHECK_REQUIREMENTS)


def prime_from_checks() -> Tuple[OpenGraphRequirement, ...]:
    """Load declarative OpenGraph requirements exposed by check classes."""
    global _CHECK_REQUIREMENTS_PRIMED
    if _CHECK_REQUIREMENTS_PRIMED:
        return registered_opengraph_requirements()

    import_module("checks")
    from checks.core.registry import CheckRegistry

    for check_class in CheckRegistry.get_all_checks():
        requirements = getattr(check_class, "OPENGRAPH_REQUIREMENTS", ())
        if requirements:
            register_opengraph_requirements(tuple(requirements))

    _CHECK_REQUIREMENTS_PRIMED = True
    return registered_opengraph_requirements()


def evaluate_opengraph_requirements(
    connection,
    payloads,
    requirements: Optional[Sequence[OpenGraphRequirement]] = None,
) -> List[OpenGraphRequirementWarning]:
    """Return warnings for imported OpenGraph nodes missing required semantics."""
    active_requirements = _active_requirements(requirements)
    warnings: List[OpenGraphRequirementWarning] = []
    for requirement in active_requirements:
        warning = _evaluate_requirement(connection, payloads, requirement)
        if warning is not None:
            warnings.append(warning)
    return warnings


def _active_requirements(
    requirements: Optional[Sequence[OpenGraphRequirement]],
) -> Tuple[OpenGraphRequirement, ...]:
    if requirements is not None:
        return tuple(requirements)
    return _merge_equivalent_requirements(
        (*BUILT_IN_OPENGRAPH_REQUIREMENTS, *registered_opengraph_requirements())
    )


def _merge_equivalent_requirements(
    requirements: Sequence[OpenGraphRequirement],
) -> Tuple[OpenGraphRequirement, ...]:
    merged: List[OpenGraphRequirement] = []
    positions = {}
    used_by_by_key = {}
    for requirement in requirements:
        key = _requirement_key(requirement)
        used_by = used_by_by_key.setdefault(key, set())
        used_by.update(requirement.used_by)
        if key not in positions:
            positions[key] = len(merged)
            merged.append(requirement)
        index = positions[key]
        merged[index] = replace(merged[index], used_by=tuple(sorted(used_by)))
    return tuple(merged)


def _requirement_key(requirement: OpenGraphRequirement) -> tuple:
    relationship = requirement.required_relationship
    return (
        requirement.name,
        requirement.when_label,
        relationship.from_label,
        relationship.relationship,
        relationship.to_label,
        relationship.direction,
        requirement.warning,
    )


def _evaluate_requirement(
    connection,
    payloads,
    requirement: OpenGraphRequirement,
) -> Optional[OpenGraphRequirementWarning]:
    subject_label = requirement.when_label
    relationship = requirement.required_relationship
    from_label = relationship.from_label
    rel_type = relationship.relationship
    to_label = relationship.to_label

    object_ids = _imported_subject_ids(payloads, subject_label)
    if not object_ids:
        return None

    query = _missing_relationship_query(
        subject_label,
        from_label,
        rel_type,
        to_label,
        relationship.direction,
    )
    result = connection.query(
        query,
        parameters={"object_ids": sorted(object_ids)},
    )
    if not result:
        return None

    missing = int(result[0].get("missing") or 0)
    if not missing:
        return None

    examples = tuple(
        str(value)
        for value in result[0].get("examples", [])
        if value
    )
    return OpenGraphRequirementWarning(
        requirement_name=requirement.name,
        subject_label=subject_label,
        warning=requirement.warning,
        missing_count=missing,
        example_names=examples,
        used_by=tuple(requirement.used_by),
    )


def _imported_subject_ids(payloads, subject_label: str) -> set:
    object_ids = set()
    for _, body, merge_mode in payloads:
        if merge_mode != "opengraph":
            continue
        graph = body.get("graph", {})
        for node in graph.get("nodes", []):
            labels = node.get("kinds") or []
            if subject_label not in labels:
                continue
            object_id = node.get("id")
            if object_id:
                object_ids.add(str(object_id))
    return object_ids


def _missing_relationship_query(
    subject_label: str,
    from_label: str,
    rel_type: str,
    to_label: str,
    direction: str,
) -> str:
    if direction == "incoming":
        missing_pattern = (
            f"MATCH (source:`{from_label}`)-[:`{rel_type}`]->(subject)"
        )
    else:
        missing_pattern = (
            f"MATCH (subject)-[:`{rel_type}`]->(target:`{to_label}`)"
        )

    return f"""
        MATCH (subject:`{subject_label}`)
        WHERE subject.objectid IN $object_ids
          AND NOT EXISTS {{
            {missing_pattern}
          }}
        WITH subject
        ORDER BY coalesce(subject.name, subject.objectid)
        RETURN count(subject) AS missing,
               collect(coalesce(subject.name, subject.objectid))[0..3] AS examples
        """
