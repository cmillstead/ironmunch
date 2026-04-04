"""Health-check / status tool."""

import os
from typing import Optional

from ..core.boundaries import make_meta
from ..security import _NO_REDACT
from ..storage import IndexStore, INDEX_VERSION
from ._common import timed, elapsed_ms
from mcp.types import ToolAnnotations
from .registry import ToolSpec, register


def get_status(storage_path: Optional[str] = None) -> dict:
    """Return a quick health-check snapshot.

    Returns:
        Dict with storage_configured, repo_count, total_symbols,
        version, and _meta envelope.
    """
    start = timed()
    store = IndexStore(base_path=storage_path)
    repos = store.list_repos()

    total_symbols = sum(r.get("symbol_count", 0) for r in repos)
    ms = elapsed_ms(start)

    # ADV-LOW-7: Removed has_api_key — leaks API key presence to MCP clients.
    # ADV-LOW-13: Redact storage_path — absolute path leaks directory structure.
    result = {
        "storage_configured": storage_path is not None or bool(os.environ.get("CODE_INDEX_PATH")),
        "repo_count": len(repos),
        "total_symbols": total_symbols,
        "version": INDEX_VERSION,
        "_meta": {
            **make_meta(source="status", trusted=True),
            "timing_ms": ms,
        },
    }

    # ADV-LOW-11: Warn when redaction is disabled
    if _NO_REDACT:
        result["redaction_disabled"] = True

    return result


_spec = register(ToolSpec(
    name="get_status",
    description="Quick health check: storage path, repo count, total symbols, and index version.",
    input_schema={
        "type": "object",
        "properties": {},
    },
    handler=lambda args, storage_path: get_status(storage_path=storage_path),
    required_args=[],
    annotations=ToolAnnotations(title="Get Status", readOnlyHint=True, openWorldHint=False),
))
