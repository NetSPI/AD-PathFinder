import re


CYPHER_IDENTIFIER_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')


def safe_cypher_identifier(value: str, kind: str) -> str:
    if not isinstance(value, str) or not CYPHER_IDENTIFIER_RE.fullmatch(value):
        raise ValueError(f"Unsupported {kind} identifier: {value!r}")
    return value


def reserved_labels() -> frozenset:
    from .opengraph_collectors import prime_from_collectors

    labels = {'Base'}
    for manifest in prime_from_collectors():
        labels.update(manifest.reserved_labels)
    return frozenset(labels)
