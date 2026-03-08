"""Transitive impact analysis -- everything affected if a symbol changes."""

from collections import deque
from typing import Optional

from ..core.boundaries import make_meta, wrap_untrusted_content
from ._common import prepare_graph_query, timed, elapsed_ms
from .registry import ToolSpec, register


def get_impact(
    repo: str,
    symbol_id: str,
    max_depth: int = 3,
    storage_path: Optional[str] = None,
) -> dict:
    """Transitive impact analysis for a symbol.

    Finds everything that would be affected if this symbol changes:
    callers, inheritors, and importers of the symbol's file.

    Args:
        repo: Repository identifier (owner/repo or just repo name).
        symbol_id: Symbol ID to analyze impact for.
        max_depth: Maximum traversal depth (default 3, max 10).
        storage_path: Custom storage path.

    Returns:
        Dict with impacted symbols/files and _meta envelope.
    """
    start = timed()

    result = prepare_graph_query(repo, symbol_id, storage_path)
    if isinstance(result, dict):
        return result
    owner, name, index, graph, target = result

    # Clamp max_depth
    max_depth = min(max(max_depth, 1), 10)

    target_name = target.get("name", "")
    target_file = target.get("file", "")

    # Multi-relationship BFS using graph adjacency lists
    visited: set[str] = {symbol_id}
    impacted: list[dict] = []

    # Queue entries: (symbol_id, current_depth)
    queue: deque[tuple[str, int]] = deque()

    # Seed: find all directly affected symbols via calls, inheritance, imports
    def _collect_affected(sid: str, depth: int) -> None:
        """Collect symbols affected by *sid* through all relationship types."""
        # Callers (reverse call edges)
        for caller_id in graph.get_callers(sid):
            if caller_id not in visited:
                visited.add(caller_id)
                sym = graph._symbols_by_id.get(caller_id, {})
                impacted.append({
                    "id": wrap_untrusted_content(caller_id),
                    "name": wrap_untrusted_content(sym.get("name", "")),
                    "kind": sym.get("kind", ""),
                    "file": wrap_untrusted_content(sym.get("file", "")),
                    "line": sym.get("line", 0),
                    "relationship": "calls",
                    "depth": depth,
                })
                if depth < max_depth:
                    queue.append((caller_id, depth + 1))

        # Inheritance children (reverse inherits edges)
        hierarchy = graph.get_type_hierarchy(sid)
        for child_id in hierarchy["children"]:
            if child_id not in visited and child_id in graph._symbols_by_id:
                visited.add(child_id)
                sym = graph._symbols_by_id[child_id]
                impacted.append({
                    "id": wrap_untrusted_content(child_id),
                    "name": wrap_untrusted_content(sym.get("name", "")),
                    "kind": sym.get("kind", ""),
                    "file": wrap_untrusted_content(sym.get("file", "")),
                    "line": sym.get("line", 0),
                    "relationship": "inherits",
                    "depth": depth,
                })
                if depth < max_depth:
                    queue.append((child_id, depth + 1))

        for impl_id in hierarchy["implemented_by"]:
            if impl_id not in visited and impl_id in graph._symbols_by_id:
                visited.add(impl_id)
                sym = graph._symbols_by_id[impl_id]
                impacted.append({
                    "id": wrap_untrusted_content(impl_id),
                    "name": wrap_untrusted_content(sym.get("name", "")),
                    "kind": sym.get("kind", ""),
                    "file": wrap_untrusted_content(sym.get("file", "")),
                    "line": sym.get("line", 0),
                    "relationship": "implements",
                    "depth": depth,
                })
                if depth < max_depth:
                    queue.append((impl_id, depth + 1))

        # File importers -- only for the root symbol's file
        if depth == 1 and target_file:
            file_base = target_file.rsplit("/", 1)[-1].rsplit(".", 1)[0]
            file_module = target_file.rsplit(".", 1)[0]
            for import_name in (target_file, file_base, file_module):
                for importer_file in graph.get_importers(import_name):
                    # Find symbols in that file
                    for sid2, sym in graph._symbols_by_id.items():
                        if sym.get("file") == importer_file and sid2 not in visited:
                            visited.add(sid2)
                            impacted.append({
                                "id": wrap_untrusted_content(sid2),
                                "name": wrap_untrusted_content(sym.get("name", "")),
                                "kind": sym.get("kind", ""),
                                "file": wrap_untrusted_content(sym.get("file", "")),
                                "line": sym.get("line", 0),
                                "relationship": "imports",
                                "depth": depth,
                            })
                            if depth < max_depth:
                                queue.append((sid2, depth + 1))

    # Collect depth-1 impacts
    _collect_affected(symbol_id, 1)

    # Continue BFS for transitive impact
    while queue:
        current_id, depth = queue.popleft()
        if depth > max_depth:
            continue
        _collect_affected(current_id, depth)

    # Collect unique affected files
    affected_files = sorted({
        entry["file"] for entry in impacted
    })

    ms = elapsed_ms(start)

    return {
        "repo": f"{owner}/{name}",
        "symbol_id": wrap_untrusted_content(symbol_id),
        "symbol_name": wrap_untrusted_content(target_name),
        "max_depth": max_depth,
        "impacted_count": len(impacted),
        "affected_file_count": len(affected_files),
        "impacted": impacted,
        "affected_files": affected_files,
        "_meta": {
            **make_meta(source="code_index", trusted=False),
            "timing_ms": ms,
        },
    }


_spec = register(ToolSpec(
    name="get_impact",
    description=(
        "Transitive impact analysis -- find everything affected if a "
        "symbol changes. Traces callers, inheritors, and importers."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "repo": {
                "type": "string",
                "description": "Repository identifier (owner/repo or just repo name)",
            },
            "symbol_id": {
                "type": "string",
                "description": "Symbol ID to analyze impact for",
            },
            "max_depth": {
                "type": "integer",
                "description": "Maximum traversal depth (default 3, max 10)",
                "default": 3,
            },
        },
        "required": ["repo", "symbol_id"],
    },
    handler=lambda args, storage_path: get_impact(
        repo=args["repo"],
        symbol_id=args["symbol_id"],
        max_depth=args.get("max_depth", 3),
        storage_path=storage_path,
    ),
    untrusted=True,
    required_args=["repo", "symbol_id"],
))
