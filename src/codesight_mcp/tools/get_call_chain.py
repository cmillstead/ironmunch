"""Find call paths between two symbols in the call graph."""

from typing import Optional

from ..core.boundaries import make_meta, wrap_untrusted_content
from ._common import prepare_graph_query, timed, elapsed_ms


def get_call_chain(
    repo: str,
    from_symbol: str,
    to_symbol: str,
    max_depth: int = 10,
    storage_path: Optional[str] = None,
) -> dict:
    """Find call paths between two symbols.

    Args:
        repo: Repository identifier (owner/repo or just repo name).
        from_symbol: Starting symbol ID.
        to_symbol: Target symbol ID.
        max_depth: Maximum path length to search (default 10, max 10).
        storage_path: Custom storage path.

    Returns:
        Dict with list of paths and _meta envelope.
    """
    start = timed()

    # Validate from_symbol via the shared helper
    result = prepare_graph_query(repo, from_symbol, storage_path)
    if isinstance(result, dict):
        return result
    owner, name, index, graph, from_sym = result

    # Verify to_symbol exists
    to_sym = index.get_symbol(to_symbol)
    if not to_sym:
        return {"error": f"Symbol not found: {to_symbol}"}

    # Clamp max_depth
    max_depth = min(max(max_depth, 1), 10)

    # Use CodeGraph.get_call_chain for path finding
    paths = graph.get_call_chain(from_symbol, to_symbol, max_depth)

    # Limit total paths to avoid excessive output
    max_paths = 5
    paths = paths[:max_paths]

    # Format paths with symbol details
    formatted_paths = []
    for path in paths:
        formatted_path = []
        for sid in path:
            sym = graph._symbols_by_id.get(sid)
            if sym:
                formatted_path.append({
                    "id": wrap_untrusted_content(sid),
                    "name": wrap_untrusted_content(sym.get("name", "")),
                    "kind": sym.get("kind", ""),
                    "file": wrap_untrusted_content(sym.get("file", "")),
                    "line": sym.get("line", 0),
                })
            else:
                formatted_path.append({
                    "id": wrap_untrusted_content(sid),
                })
        formatted_paths.append(formatted_path)

    ms = elapsed_ms(start)

    return {
        "repo": f"{owner}/{name}",
        "from_symbol": wrap_untrusted_content(from_symbol),
        "to_symbol": wrap_untrusted_content(to_symbol),
        "max_depth": max_depth,
        "path_count": len(formatted_paths),
        "paths": formatted_paths,
        "_meta": {
            **make_meta(source="code_index", trusted=False),
            "timing_ms": ms,
        },
    }
