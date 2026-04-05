"""Aggregate import data to show external vs internal dependencies."""

from collections import defaultdict
from typing import Optional

from ..core.boundaries import make_meta, wrap_untrusted_content
from ..parser.graph import CodeGraph, _build_import_resolution_map
from ..security import sanitize_signature_for_api
from ._common import RepoContext, timed, elapsed_ms
from mcp.types import ToolAnnotations
from .registry import ToolSpec, register


def get_dependencies(
    repo: str,
    storage_path: Optional[str] = None,
) -> dict:
    """Aggregate import data to show external vs internal dependencies.

    Collects all imports from indexed symbols, groups them by module name,
    and partitions them into external (third-party / stdlib) and internal
    (modules matching source files in the repo) dependencies.

    Args:
        repo: Repository identifier (owner/repo or just repo name).
        storage_path: Custom storage path.

    Returns:
        Dict with external/internal dependency lists and _meta envelope.
    """
    start = timed()

    ctx = RepoContext.resolve(repo, storage_path)
    if isinstance(ctx, dict):
        return ctx
    owner, name, index = ctx.owner, ctx.name, ctx.index

    # Build resolution map for internal detection
    resolution_map = _build_import_resolution_map(index.source_files)

    # Collect imports: module -> set of importing files
    module_to_files: dict[str, set[str]] = defaultdict(set)
    for sym in index.symbols:
        sym_file = sym.get("file", "")
        for imp in sym.get("imports", []):
            if not imp:
                continue
            module_to_files[imp].add(sym_file)

    # Partition into external vs internal, sorted by import_count descending
    external: list[dict] = []
    internal: list[dict] = []

    for module, importing_files in sorted(
        module_to_files.items(),
        key=lambda kv: len(kv[1]),
        reverse=True,
    ):
        entry = {
            "module": wrap_untrusted_content(sanitize_signature_for_api(module)),
            "import_count": len(importing_files),
            "imported_by": [
                wrap_untrusted_content(f) for f in sorted(importing_files)
            ],
        }
        if resolution_map.get(module) is not None:
            internal.append(entry)
        else:
            external.append(entry)

    # Circular dependency detection
    graph = CodeGraph.get_or_build(index.symbols)
    cycles, cycle_total, cycle_truncated = graph.find_import_cycles(
        index.source_files,
    )
    wrapped_cycles = [
        [wrap_untrusted_content(f) for f in scc]
        for scc in cycles
    ]

    ms = elapsed_ms(start)

    return {
        "repo": f"{owner}/{name}",
        "external": external,
        "internal": internal,
        "circular_dependencies": wrapped_cycles,
        "_meta": {
            **make_meta(source="code_index", trusted=False),
            "timing_ms": ms,
            "external_count": len(external),
            "internal_count": len(internal),
            "circular_count": cycle_total,
            "circular_truncated": cycle_truncated,
        },
    }


_spec = register(ToolSpec(
    name="get_dependencies",
    description=(
        "Aggregate import data to show external vs internal dependencies. "
        "Groups imports by module name and partitions into external (third-party/stdlib) "
        "and internal (modules matching repo source files), sorted by usage count. "
        "Also detects circular dependencies via Tarjan SCC on internal import edges."
    ),
    untrusted=True,
    input_schema={
        "type": "object",
        "properties": {
            "repo": {
                "type": "string",
                "description": "Repository identifier (owner/repo or just repo name)",
            },
        },
        "required": ["repo"],
    },
    handler=lambda args, storage_path: get_dependencies(
        repo=args["repo"],
        storage_path=storage_path,
    ),
    required_args=["repo"],
    annotations=ToolAnnotations(title="Get Dependencies", readOnlyHint=True, openWorldHint=False),
))
