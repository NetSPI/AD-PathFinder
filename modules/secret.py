from __future__ import annotations


class Secret:
    """Password wrapper. Masks under repr/str/logging; .expose() at the use site."""

    __slots__ = ("_value",)

    def __init__(self, value: str | None) -> None:
        self._value = value or ""

    def expose(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Secret('***')" if self._value else "Secret('')"

    def __str__(self) -> str:
        return "***" if self._value else ""

    def __bool__(self) -> bool:
        return bool(self._value)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Secret):
            return self._value == other._value
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._value)
