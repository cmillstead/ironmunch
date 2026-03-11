"""Rank symbols by structural importance using PageRank."""

from typing import Optional

from ..core.boundaries import make_meta, wrap_untrusted_content
from ..parser.graph import CodeGraph
from ._common import RepoContext, timed, elapsed_ms
from .registry import ToolSpec, register

_MAX_CANDIDATES = 200


def get_key_symbols(
    repo: str,
    path: Optional[str] = None,
    limit: int = 20,
    kind: Optional[str] = None,
    storage_path: Optional[str] = None,
) -> dict:
    """Rank symbols by structural importance in the codebase.

    Uses PageRank on the call graph to identify the most connected
    and depended-upon symbols.

    Args:
        repo: Repository identifier (owner/repo or just repo name).
        path: Optional file/directory prefix filter (applied after ranking).
        limit: Maximum results (default 20, max 100).
        kind: Optional kind filter ('function', 'method', 'class').
        storage_path: Custom storage path.

    Returns:
        Dict with ranked symbol list and _meta envelope.
    """
    start = timed()
    limit = max(1, min(limit, 100))

    ctx = RepoContext.resolve(repo, storage_path)
    if isinstance(ctx, dict):
        return ctx
    owner, name, index = ctx.owner, ctx.name, ctx.index

    graph = CodeGraph.get_or_build(index.symbols)

    # PageRank on full graph (scope filter applied after)
    ranks = graph.pagerank()

    # Build pre-filtered list and sort by cheap heuristic (caller count)
    # to cap expensive get_impact calls.
    pre_candidates = []
    for sym in index.symbols:
        sid = sym.get("id", "")
        if not sid:
            continue
        sym_kind = sym.get("kind", "")
        file_path = sym.get("file", "")

        # Apply filters
        if path and not file_path.startswith(path):
            continue
        if kind and sym_kind != kind:
            continue

        fan_in = len(graph.get_callers(sid))
        fan_out = len(graph.get_callees(sid))
        pre_candidates.append((sym, sid, sym_kind, file_path, fan_in, fan_out))

    # Sort by caller count (cheap heuristic) and cap to _MAX_CANDIDATES
    pre_candidates.sort(key=lambda c: c[4], reverse=True)
    pre_candidates = pre_candidates[:_MAX_CANDIDATES]

    # Build candidates with expensive impact computation
    candidates = []
    for sym, sid, sym_kind, file_path, fan_in, fan_out in pre_candidates:
        impact = graph.get_impact(sid, max_depth=3)

        candidates.append({
            "id": sid,
            "name": sym.get("name", ""),
            "kind": sym_kind,
            "file": file_path,
            "line": sym.get("line", 0),
            "rank": round(ranks.get(sid, 0.0), 4),
            "fan_in": fan_in,
            "fan_out": fan_out,
            "impact_size": len(impact),
        })

    # Sort by rank descending
    candidates.sort(key=lambda c: c["rank"], reverse=True)

    # Wrap untrusted content and truncate
    key_symbols = []
    for c in candidates[:limit]:
        key_symbols.append({
            "id": wrap_untrusted_content(c["id"]),
            "name": wrap_untrusted_content(c["name"]),
            "kind": c["kind"],
            "file": wrap_untrusted_content(c["file"]),
            "line": c["line"],
            "rank": c["rank"],
            "fan_in": c["fan_in"],
            "fan_out": c["fan_out"],
            "impact_size": c["impact_size"],
        })

    ms = elapsed_ms(start)

    return {
        "repo": f"{owner}/{name}",
        "key_symbols": key_symbols,
        "scope": path,
        "total_symbols": len(index.symbols),
        "_meta": {
            **make_meta(source="code_index", trusted=False),
            "timing_ms": ms,
        },
    }


_spec = register(ToolSpec(
    name="get_key_symbols",
    description=(
        "Rank symbols by structural importance using PageRank on the call graph. "
        "Identifies the most connected and depended-upon symbols in a codebase. "
        "Supports path and kind filtering."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "repo": {
                "type": "string",
                "description": "Repository identifier (owner/repo or just repo name)",
            },
            "path": {
                "type": "string",
                "description": "Filter to file or directory prefix (e.g. 'src/parser/')",
            },
            "limit": {
                "type": "integer",
                "description": "Maximum results (default 20, max 100)",
                "default": 20,
            },
            "kind": {
                "type": "string",
                "description": "Filter by symbol kind: 'function', 'method', or 'class'",
                "enum": ["function", "method", "class"],
            },
        },
        "required": ["repo"],
    },
    handler=lambda args, storage_path: get_key_symbols(
        repo=args["repo"],
        path=args.get("path"),
        limit=args.get("limit", 20),
        kind=args.get("kind"),
        storage_path=storage_path,
    ),
    untrusted=True,
    required_args=["repo"],
))
