from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .dependencies import CheckDependencies


class DataSource:

    def __init__(self, deps: CheckDependencies) -> None:
        self.deps = deps

    def query(self, cypher: str, parameters: dict[str, Any] | None = None,
              name: str | None = None) -> list[dict[str, Any]]:
        results = self.deps.neo4j_data.conn.query(cypher, parameters=parameters, name=name)
        return results if results else []

    def available(self) -> bool:
        raise NotImplementedError


class DataSourceRegistry:
    _datasources: dict[str, type] = {}

    @classmethod
    def register(cls, name: str, datasource_class: type) -> None:
        cls._datasources[name] = datasource_class

    @classmethod
    def get_all(cls) -> dict[str, type]:
        return dict(cls._datasources)


def datasource(name: str) -> Callable[[type], type]:
    def decorator(cls):
        DataSourceRegistry.register(name, cls)
        return cls
    return decorator
