"""Invalidate cache / delete index tool."""

from typing import Optional

from ..core.errors import sanitize_error, RepoNotFoundError
from ..storage import IndexStore
from ._common import parse_repo


def invalidate_cache(
    repo: str,
    storage_path: Optional[str] = None,
) -> dict:
    """Delete an index and all cached data for a repository.

    This is an alias for delete_index that also ensures any in-memory
    state is cleared. Use when you want to force a full re-index.

    Args:
        repo: Repository identifier (owner/repo or just repo name).
        storage_path: Custom storage path.

    Returns:
        Dict with success status.
    """
    # --- security gate: parse + validate repo identifier ---
    try:
        owner, name = parse_repo(repo, storage_path)
    except RepoNotFoundError as exc:
        return {"error": str(exc)}

    try:
        store = IndexStore(base_path=storage_path)
        deleted = store.delete_index(owner, name)
    except Exception as exc:
        return {"error": sanitize_error(exc)}

    if deleted:
        return {
            "success": True,
            "repo": f"{owner}/{name}",
            "message": f"Index and cached files deleted for {owner}/{name}",
        }
    else:
        return {
            "success": False,
            "error": f"No index found for {owner}/{name}",
        }
