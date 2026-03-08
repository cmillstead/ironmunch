"""Get callees of a symbol -- forward call graph traversal."""

from collections import deque
from typing import Optional

from ..core.boundaries import make_meta, wrap_untrusted_content
from ._common import prepare_graph_query, timed, elapsed_ms
from .registry import ToolSpec, register


def get_callees(
    repo: str,
    symbol_id: str,
    max_depth: int = 1,
    storage_path: Optional[str] = None,
) -> dict:
    """Get symbols that the specified symbol calls.

    Args:
        repo: Repository identifier (owner/repo or just repo name).
        symbol_id: Symbol ID to find callees of.
        max_depth: Maximum traversal depth (1 = direct callees only, max 5).
        storage_path: Custom storage path.

    Returns:
        Dict with callee list and _meta envelope.
    """
    start = timed()

    result = prepare_graph_query(repo, symbol_id, storage_path)
    if isinstance(result, dict):
        return result
    owner, name, index, graph, target = result

    # Clamp max_depth
    max_depth = min(max(max_depth, 1), 5)

    # BFS over graph.get_callees() for transitive lookup
    visited: set[str] = {symbol_id}
    callees: list[dict] = []
    queue: deque[tuple[str, int]] = deque()
    queue.append((symbol_id, 1))

    while queue:
        current_id, depth = queue.popleft()
        if depth > max_depth:
            continue

        for callee_id in graph.get_callees(current_id):
            if callee_id in visited:
                continue
            visited.add(callee_id)
            sym = graph._symbols_by_id.get(callee_id, {})
            callees.append({
                "id": wrap_untrusted_content(callee_id),
                "name": wrap_untrusted_content(sym.get("name", "")),
                "kind": sym.get("kind", ""),
                "file": wrap_untrusted_content(sym.get("file", "")),
                "line": sym.get("line", 0),
                "depth": depth,
            })
            if depth < max_depth:
                queue.append((callee_id, depth + 1))

    ms = elapsed_ms(start)

    target_name = target.get("name", "")

    return {
        "repo": f"{owner}/{name}",
        "symbol_id": wrap_untrusted_content(symbol_id),
        "symbol_name": wrap_untrusted_content(target_name),
        "max_depth": max_depth,
        "callee_count": len(callees),
        "callees": callees,
        "_meta": {
            **make_meta(source="code_index", trusted=False),
            "timing_ms": ms,
        },
    }


_spec = register(ToolSpec(
    name="get_callees",
    description=(
        "Get symbols that a specified symbol calls. Supports transitive "
        "callee traversal up to a configurable depth."
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
                "description": "Symbol ID to find callees of",
            },
            "max_depth": {
                "type": "integer",
                "description": "Maximum traversal depth (1 = direct callees only, max 5)",
                "default": 1,
            },
        },
        "required": ["repo", "symbol_id"],
    },
    handler=lambda args, storage_path: get_callees(
        repo=args["repo"],
        symbol_id=args["symbol_id"],
        max_depth=args.get("max_depth", 1),
        storage_path=storage_path,
    ),
    untrusted=True,
    required_args=["repo", "symbol_id"],
))
