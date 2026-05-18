from __future__ import annotations

from collections.abc import Callable

from .base import VulnerabilityCheck as Check
from .datasource import DataSource, datasource
from .registry import CheckRegistry
from .constants import DisplayTypes


def check(risk: str, category: str, entity: str | None = None,
          data: list[str] | None = None, display: str | None = None,
          section: str | None = None,
          requires: list[str] | None = None) -> Callable[[type], type]:
    def decorator(cls):
        cls.RISK_LEVEL = risk
        cls.CATEGORY_NAME = category
        if entity is not None:
            cls.ENTITY_TYPE = entity
        if data is not None:
            cls.REQUIRED_DATA = data
        if display is not None:
            cls.DISPLAY_TYPE = display
        else:
            cls.DISPLAY_TYPE = DisplayTypes.SIMPLE
        if section is not None:
            cls.SECTION = section
        if requires is not None:
            cls.REQUIRES = requires
        CheckRegistry.register(cls)
        return cls
    return decorator
