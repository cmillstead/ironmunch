"""Find complex and risky symbols in a codebase."""

from typing import Optional

from ..core.boundaries import make_meta, wrap_untrusted_content
from ..parser.graph import CodeGraph
from ._common import RepoContext, timed, elapsed_ms
from .registry import ToolSpec, register


_VALID_SORT_BY = {"risk", "complexity", "cognitive"}


def _normalize(values: list[float]) -> list[float]:
    """Min-max normalize a list of floats to [0, 1]."""
    if not values:
        return values
    lo, hi = min(values), max(values)
    span = hi - lo
    if span == 0:
        return [0.0] * len(values)
    return [(v - lo) / span for v in values]


def get_hotspots(
    repo: str,
    path: Optional[str] = None,
    limit: int = 20,
    sort_by: str = "risk",
    storage_path: Optional[str] = None,
) -> dict:
    """Find the most complex/risky symbols in a repo.

    Args:
        repo: Repository identifier (owner/repo or just repo name).
        path: Optional file/directory prefix filter.
        limit: Maximum results (default 20, max 100).
        sort_by: Sort mode — 'risk' (default), 'complexity', or 'cognitive'.
        storage_path: Custom storage path.

    Returns:
        Dict with ranked hotspot list and _meta envelope.
    """
    if sort_by not in _VALID_SORT_BY:
        return {"error": f"Invalid sort_by: must be one of {sorted(_VALID_SORT_BY)}"}

    start = timed()
    limit = max(1, min(limit, 100))

    if path:
        if "\x00" in path:
            return {"error": "path contains null bytes"}
        if any(part == ".." for part in path.split("/")):
            return {"error": "path traversal not allowed"}

    ctx = RepoContext.resolve(repo, storage_path)
    if isinstance(ctx, dict):
        return ctx
    owner, name, index = ctx.owner, ctx.name, ctx.index

    graph = CodeGraph.get_or_build(index.symbols)

    # Collect executable symbols with complexity data
    candidates = []
    for sym in index.symbols:
        sid = sym.get("id", "")
        if not sid:
            continue
        kind = sym.get("kind", "")
        if kind not in ("function", "method"):
            continue
        cx = sym.get("complexity", {})
        if not cx:
            continue
        file_path = sym.get("file", "")
        if path and not file_path.startswith(path):
            continue

        fan_in = len(graph.get_callers(sid))
        fan_out = len(graph.get_callees(sid))

        candidates.append({
            "id": sid,
            "name": sym.get("name", ""),
            "kind": kind,
            "file": file_path,
            "line": sym.get("line", 0),
            "cyclomatic": cx.get("cyclomatic", 1),
            "cognitive": cx.get("cognitive", 0),
            "max_nesting": cx.get("max_nesting", 0),
            "param_count": cx.get("param_count", 0),
            "loc": cx.get("loc", 0),
            "fan_in": fan_in,
            "fan_out": fan_out,
        })

    if not candidates:
        ms = elapsed_ms(start)
        return {
            "repo": f"{owner}/{name}",
            "hotspots": [],
            "scope": path,
            "_meta": {**make_meta(source="code_index", trusted=False), "timing_ms": ms},
        }

    # Sort
    if sort_by == "complexity":
        candidates.sort(key=lambda c: c["cyclomatic"], reverse=True)
    elif sort_by == "cognitive":
        candidates.sort(key=lambda c: c["cognitive"], reverse=True)
    else:
        # Composite risk score
        cognitives = _normalize([c["cognitive"] for c in candidates])
        cyclomatics = _normalize([c["cyclomatic"] for c in candidates])
        fan_ins = _normalize([float(c["fan_in"]) for c in candidates])
        nestings = _normalize([float(c["max_nesting"]) for c in candidates])

        for i, c in enumerate(candidates):
            c["risk_score"] = round(
                0.4 * cognitives[i]
                + 0.3 * cyclomatics[i]
                + 0.2 * fan_ins[i]
                + 0.1 * nestings[i],
                3,
            )
        candidates.sort(key=lambda c: c.get("risk_score", 0), reverse=True)

    # Truncate and wrap untrusted content
    hotspots = []
    for c in candidates[:limit]:
        entry = {
            "id": wrap_untrusted_content(c["id"]),
            "name": wrap_untrusted_content(c["name"]),
            "kind": c["kind"],
            "file": wrap_untrusted_content(c["file"]),
            "line": c["line"],
            "cyclomatic": c["cyclomatic"],
            "cognitive": c["cognitive"],
            "max_nesting": c["max_nesting"],
            "param_count": c["param_count"],
            "loc": c["loc"],
            "fan_in": c["fan_in"],
            "fan_out": c["fan_out"],
        }
        if "risk_score" in c:
            entry["risk_score"] = c["risk_score"]
        hotspots.append(entry)

    ms = elapsed_ms(start)

    return {
        "repo": f"{owner}/{name}",
        "hotspot_count": len(hotspots),
        "hotspots": hotspots,
        "scope": path,
        "_meta": {
            **make_meta(source="code_index", trusted=False),
            "timing_ms": ms,
        },
    }


_spec = register(ToolSpec(
    name="get_hotspots",
    description=(
        "Find the most complex and risky symbols in a codebase. "
        "Returns cyclomatic complexity, cognitive complexity, nesting depth, "
        "fan-in/fan-out, and a composite risk score. "
        "Supports path filtering and multiple sort modes."
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
            "sort_by": {
                "type": "string",
                "description": "Sort mode: 'risk' (default), 'complexity', or 'cognitive'",
                "enum": ["risk", "complexity", "cognitive"],
                "default": "risk",
            },
        },
        "required": ["repo"],
    },
    handler=lambda args, storage_path: get_hotspots(
        repo=args["repo"],
        path=args.get("path"),
        limit=args.get("limit", 20),
        sort_by=args.get("sort_by", "risk"),
        storage_path=storage_path,
    ),
    untrusted=True,
    required_args=["repo"],
))
