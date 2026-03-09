"""Health-check / status tool."""

from typing import Optional

from ..core.boundaries import make_meta
from ..storage import IndexStore, INDEX_VERSION
from ._common import timed, elapsed_ms
from .registry import ToolSpec, register


def status(storage_path: Optional[str] = None) -> dict:
    """Return a quick health-check snapshot.

    Returns:
        Dict with storage_path, repo_count, total_symbols,
        version, and _meta envelope.
    """
    start = timed()
    store = IndexStore(base_path=storage_path)
    repos = store.list_repos()

    total_symbols = sum(r.get("symbol_count", 0) for r in repos)
    ms = elapsed_ms(start)

    # ADV-LOW-7: Removed has_api_key — leaks API key presence to MCP clients.
    return {
        "storage_path": str(store.base_path),
        "repo_count": len(repos),
        "total_symbols": total_symbols,
        "version": INDEX_VERSION,
        "_meta": {
            **make_meta(source="status", trusted=True),
            "timing_ms": ms,
        },
    }


_spec = register(ToolSpec(
    name="status",
    description="Quick health check: storage path, repo count, total symbols, and index version.",
    input_schema={
        "type": "object",
        "properties": {},
    },
    handler=lambda args, storage_path: status(storage_path=storage_path),
    required_args=[],
))
