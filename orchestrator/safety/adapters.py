"""Typed tool adapters callable only through the execution gateway."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from types import MappingProxyType
from typing import Any, Protocol

from ..tool_registry import SideEffect, TOOL_REGISTRY
from .contracts import AdapterExecution


AdapterHandler = Callable[[dict[str, Any]], Awaitable[Any]]
_MUTATING_EFFECTS = {
    SideEffect.ARBITRARY_CODE,
    SideEffect.EXTERNAL_COMMUNICATION,
    SideEffect.FILE_WRITE,
    SideEffect.MEMORY_WRITE,
    SideEffect.PROCESS_LAUNCH,
    SideEffect.SCHEDULE_CHANGE,
    SideEffect.SYSTEM_STATE_CHANGE,
    SideEffect.UI_CONTROL,
}


class ToolAdapter(Protocol):
    name: str
    side_effect_possible: bool

    async def execute(self, arguments: dict[str, Any]) -> AdapterExecution: ...


class CallableToolAdapter:
    def __init__(self, name: str, handler: AdapterHandler) -> None:
        if name not in TOOL_REGISTRY:
            raise ValueError("adapter tool is not registered")
        self.name = name
        self.handler = handler
        self.side_effect_possible = bool(
            TOOL_REGISTRY[name].side_effects & _MUTATING_EFFECTS
        )

    async def execute(self, arguments: dict[str, Any]) -> AdapterExecution:
        output = await self.handler(dict(arguments))
        return AdapterExecution(
            output=output,
            side_effect_occurred=self.side_effect_possible,
        )


class ToolAdapterRegistry:
    def __init__(
        self,
        adapters: Mapping[str, ToolAdapter],
        *,
        require_complete: bool = True,
    ) -> None:
        unknown = set(adapters) - set(TOOL_REGISTRY)
        mismatched = {
            name for name, adapter in adapters.items() if adapter.name != name
        }
        from ..tool_declarations import RETIRED_TOOL_NAMES
        missing = (set(TOOL_REGISTRY) - RETIRED_TOOL_NAMES - set(adapters)) if require_complete else set()
        if unknown or mismatched or missing:
            raise ValueError(
                "invalid tool adapter registry: "
                f"unknown={sorted(unknown)}, mismatched={sorted(mismatched)}, "
                f"missing={sorted(missing)}"
            )
        self._adapters = MappingProxyType(dict(adapters))

    def get(self, tool_name: str) -> ToolAdapter | None:
        return self._adapters.get(tool_name)

    @property
    def names(self) -> frozenset[str]:
        return frozenset(self._adapters)
