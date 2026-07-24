"""Resolved (import/scope-aware) call-graph resolution. Spec: SPEC_5 §3. Milestone: M7."""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..storage.index_store import CodeIndex


def build_import_map(file_symbols: list[dict], language: str) -> dict[str, str]:
    """Map local alias -> fully-qualified module/symbol for one file. Spec: SPEC_5 §3.2."""
    raise NotImplementedError("M7 — SPEC_5 §3.2")


def resolve_call_edges(index: "CodeIndex") -> list[dict]:
    """Second pass: convert name-based edges to resolved edges. Spec: SPEC_5 §3.3."""
    raise NotImplementedError("M7 — SPEC_5 §3.3")
