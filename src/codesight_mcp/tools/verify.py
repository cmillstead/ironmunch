"""Index health verification tool for CI gates."""

from datetime import datetime, timezone
from typing import Optional

from mcp.types import ToolAnnotations

from ..core.boundaries import make_meta, wrap_untrusted_content
from ..storage import INDEX_VERSION
from ._common import RepoContext, timed, elapsed_ms
from .registry import ToolSpec, register


def verify(
    repo: str,
    max_age_hours: int = 168,
    storage_path: Optional[str] = None,
) -> dict:
    """Fast pass/fail health check for CI gates.

    Validates index existence, version, freshness, symbol count,
    and content file integrity via deterministic sampling.
    """
    start = timed()

    ctx = RepoContext.resolve(repo, storage_path)
    if isinstance(ctx, dict):
        return ctx

    checks: dict[str, dict] = {}

    # Check 1: exists (already passed if RepoContext resolved)
    checks["exists"] = {"passed": True}

    # Check 2: version
    version_ok = ctx.index.index_version == INDEX_VERSION
    checks["version"] = {
        "passed": version_ok,
        "current": ctx.index.index_version,
        "expected": INDEX_VERSION,
    }

    # Check 3: freshness
    try:
        indexed_dt = datetime.fromisoformat(ctx.index.indexed_at)
        age_hours = (datetime.now(timezone.utc) - indexed_dt).total_seconds() / 3600
        fresh = age_hours <= max_age_hours
    except (ValueError, TypeError):
        age_hours = -1
        fresh = False
    checks["freshness"] = {
        "passed": fresh,
        "indexed_at": ctx.index.indexed_at,
        "age_hours": round(age_hours, 1),
        "max_age_hours": max_age_hours,
    }

    # Check 4: symbols
    sym_count = len(ctx.index.symbols)
    checks["symbols"] = {
        "passed": sym_count > 0,
        "count": sym_count,
    }

    # Check 5: content integrity -- deterministic sample (first 5 distinct files by sorted ID)
    seen_files: set[str] = set()
    sample: list[str] = []
    for sid in sorted(s["id"] for s in ctx.index.symbols if "id" in s):
        sym = ctx.index.get_symbol(sid)
        file_path = sym.get("file", "") if sym else ""
        if file_path not in seen_files:
            seen_files.add(file_path)
            sample.append(sid)
            if len(sample) >= 5:
                break
    readable = 0
    for sid in sample:
        try:
            content = ctx.store.get_symbol_content(
                ctx.owner, ctx.name, sid, index=ctx.index,
            )
            if content:
                readable += 1
        except Exception:
            pass  # Count as unreadable
    checks["content_integrity"] = {
        "passed": readable == len(sample) if sample else True,
        "sampled": len(sample),
        "readable": readable,
    }

    passed = all(c["passed"] for c in checks.values())
    ms = elapsed_ms(start)

    return {
        "repo": wrap_untrusted_content(f"{ctx.owner}/{ctx.name}"),
        "passed": passed,
        "checks": checks,
        "_meta": {
            **make_meta(source="verify", trusted=False),
            "timing_ms": ms,
        },
    }


_spec = register(ToolSpec(
    name="verify",
    description=(
        "Fast pass/fail health check for CI gates. Validates index existence, "
        "version, freshness, symbol count, and content file integrity."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "repo": {
                "type": "string",
                "description": "Repository identifier (owner/repo or just repo name)",
            },
            "max_age_hours": {
                "type": "integer",
                "description": "Fail if index is older than N hours. Default: 168 (1 week).",
            },
        },
        "required": ["repo"],
    },
    handler=lambda args, storage_path: verify(
        repo=args["repo"],
        max_age_hours=args.get("max_age_hours", 168),
        storage_path=storage_path,
    ),
    required_args=["repo"],
    annotations=ToolAnnotations(
        title="Verify Index",
        readOnlyHint=True,
        openWorldHint=False,
    ),
    ci_exit_key="passed",
))
