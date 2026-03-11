"""Dead code detection -- find symbols with zero callers."""

from typing import Optional

from ..core.boundaries import make_meta, wrap_untrusted_content
from ..parser.graph import CodeGraph
from ._common import RepoContext, timed, elapsed_ms
from .registry import ToolSpec, register


_MAX_DEAD_CODE = 500


# Names that are typically entry points and should not be flagged.
_ENTRY_POINT_NAMES = frozenset({
    "main",
    "__init__",
    "__main__",
    "__post_init__",
    "__new__",
    "__del__",
    "__str__",
    "__repr__",
    "__eq__",
    "__hash__",
    "__lt__",
    "__le__",
    "__gt__",
    "__ge__",
    "__len__",
    "__getitem__",
    "__setitem__",
    "__delitem__",
    "__contains__",
    "__iter__",
    "__next__",
    "__enter__",
    "__exit__",
    "__call__",
    "__bool__",
    "__add__",
    "__sub__",
    "__mul__",
    "__truediv__",
})


def _is_test_file(file_path: str) -> bool:
    """Return True if *file_path* looks like a test file."""
    parts = file_path.replace("\\", "/").split("/")
    filename = parts[-1] if parts else file_path
    return (
        filename.startswith("test_")
        or filename.endswith("_test.py")
        or filename.endswith("_test.go")
        or filename.endswith(".test.js")
        or filename.endswith(".test.ts")
        or filename.endswith(".test.tsx")
        or filename.endswith(".test.jsx")
        or filename.endswith("_spec.rb")
        or filename.endswith("Test.java")
        or filename.endswith("Test.kt")
        or "/tests/" in file_path
        or "/__tests__/" in file_path
        or file_path.startswith("test/")
        or file_path.startswith("tests/")
        or file_path.startswith("__tests__/")
    )


def _is_entry_point(sym: dict) -> bool:
    """Return True if a symbol looks like an entry point or exported symbol."""
    name = sym.get("name", "")

    # Well-known entry point names
    if name in _ENTRY_POINT_NAMES:
        return True

    # Test functions / methods
    if name.startswith("test_") or name.startswith("Test"):
        return True

    # Decorated entry points (e.g., @app.route, @pytest.fixture)
    decorators = sym.get("decorators", [])
    for dec in decorators:
        dec_lower = str(dec).lower() if dec else ""
        if any(kw in dec_lower for kw in (
            "route", "endpoint", "fixture", "hook",
            "export", "main", "cli", "command",
            "app.", "api.", "pytest.",
        )):
            return True

    return False


def get_dead_code(
    repo: str,
    language: Optional[str] = None,
    include_tests: bool = False,
    limit: int = 100,
    storage_path: Optional[str] = None,
) -> dict:
    """Find symbols with zero callers (potentially dead code).

    Args:
        repo: Repository identifier (owner/repo or just repo name).
        language: Optional language filter (e.g. "python", "javascript").
        include_tests: If True, include symbols from test files (default False).
        limit: Maximum results to return (default 100, max 500).
        storage_path: Custom storage path.

    Returns:
        Dict with list of potentially dead symbols and _meta envelope.
    """
    start = timed()

    limit = max(1, min(limit, _MAX_DEAD_CODE))

    ctx = RepoContext.resolve(repo, storage_path)
    if isinstance(ctx, dict):
        return ctx
    owner, name, index = ctx.owner, ctx.name, ctx.index

    graph = CodeGraph.get_or_build(index.symbols)

    dead: list[dict] = []

    for sym in index.symbols:
        if len(dead) >= limit:
            break
        sid = sym.get("id", "")
        if not sid:
            continue

        # Language filter
        if language and sym.get("language", "").lower() != language.lower():
            continue

        # Exclude test files unless requested
        file_path = sym.get("file", "")
        if not include_tests and _is_test_file(file_path):
            continue

        # Skip entry points
        if _is_entry_point(sym):
            continue

        # Check for zero callers
        callers = graph.get_callers(sid)
        if len(callers) == 0:
            dead.append({
                "id": wrap_untrusted_content(sid),
                "name": wrap_untrusted_content(sym.get("name", "")),
                "kind": sym.get("kind", ""),
                "file": wrap_untrusted_content(file_path),
                "line": sym.get("line", 0),
                "language": sym.get("language", ""),
            })

    truncated = len(dead) >= limit

    ms = elapsed_ms(start)

    return {
        "repo": f"{owner}/{name}",
        "dead_count": len(dead),
        "truncated": truncated,
        "symbols": dead,
        "_meta": {
            **make_meta(source="code_index", trusted=False),
            "timing_ms": ms,
        },
    }


_spec = register(ToolSpec(
    name="get_dead_code",
    description=(
        "Find potentially dead code -- symbols with zero callers. "
        "Filters out known entry points, test functions, and dunder methods."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "repo": {
                "type": "string",
                "description": "Repository identifier (owner/repo or just repo name)",
            },
            "language": {
                "type": "string",
                "description": "Filter by language (e.g. 'python', 'javascript')",
            },
            "include_tests": {
                "type": "boolean",
                "description": "Include symbols from test files (default false)",
                "default": False,
            },
            "limit": {
                "type": "integer",
                "description": "Maximum results to return (default 100, max 500)",
                "default": 100,
            },
        },
        "required": ["repo"],
    },
    handler=lambda args, storage_path: get_dead_code(
        repo=args["repo"],
        language=args.get("language"),
        include_tests=args.get("include_tests", False),
        limit=args.get("limit", 100),
        storage_path=storage_path,
    ),
    untrusted=True,
    required_args=["repo"],
))
