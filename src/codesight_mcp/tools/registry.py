"""Declarative tool registry -- each tool file exports a ToolSpec."""

from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class ToolSpec:
    """Everything server.py needs to register and dispatch a tool."""

    name: str
    description: str
    input_schema: dict
    handler: Callable[..., Any]
    untrusted: bool = False
    index_gate: bool = False
    destructive: bool = False
    text_search: bool = False
    required_args: list[str] = field(default_factory=list)


_REGISTRY: dict[str, ToolSpec] = {}


def register(spec: ToolSpec) -> ToolSpec:
    """Register a tool spec. Raises ValueError on duplicate name."""
    if spec.name in _REGISTRY:
        raise ValueError(f"Duplicate tool registration: {spec.name}")
    _REGISTRY[spec.name] = spec
    return spec


def get_all_specs() -> dict[str, ToolSpec]:
    """Return a copy of the registry."""
    return dict(_REGISTRY)


def _snapshot_registry() -> dict[str, ToolSpec]:
    """Snapshot the registry state. For testing only."""
    return dict(_REGISTRY)


def _restore_registry(snapshot: dict[str, ToolSpec]) -> None:
    """Restore the registry to a previous snapshot. For testing only."""
    _REGISTRY.clear()
    _REGISTRY.update(snapshot)
