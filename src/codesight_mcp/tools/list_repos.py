"""List indexed repositories."""

from typing import Optional

from ..core.boundaries import make_meta, wrap_untrusted_content
from ..storage import IndexStore
from ._common import timed, elapsed_ms
from .registry import ToolSpec, register


def list_repos(storage_path: Optional[str] = None) -> dict:
    """List all indexed repositories.

    Returns:
        Dict with count, list of repos, and _meta envelope.
    """
    start = timed()
    store = IndexStore(base_path=storage_path)
    repos = store.list_repos()
    ms = elapsed_ms(start)

    # Wrap repo names — directory names come from disk and are attacker-influenced
    for r in repos:
        if "repo" not in r:
            continue
        r["repo"] = wrap_untrusted_content(r["repo"])

    return {
        "count": len(repos),
        "repos": repos,
        "_meta": {
            **make_meta(source="index_list", trusted=True),
            "timing_ms": ms,
        },
    }


_spec = register(ToolSpec(
    name="list_repos",
    description="List all indexed repositories.",
    input_schema={
        "type": "object",
        "properties": {},
    },
    handler=lambda args, storage_path: list_repos(storage_path=storage_path),
    required_args=[],
))
