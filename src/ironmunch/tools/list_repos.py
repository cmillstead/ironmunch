"""List indexed repositories."""

from typing import Optional

from ..core.boundaries import make_meta
from ..storage import IndexStore
from ._common import timed, elapsed_ms


def list_repos(storage_path: Optional[str] = None) -> dict:
    """List all indexed repositories.

    Returns:
        Dict with count, list of repos, and _meta envelope.
    """
    start = timed()
    store = IndexStore(base_path=storage_path)
    repos = store.list_repos()
    ms = elapsed_ms(start)

    return {
        "count": len(repos),
        "repos": repos,
        "_meta": {
            **make_meta(source="index_list", trusted=True),
            "timing_ms": ms,
        },
    }
