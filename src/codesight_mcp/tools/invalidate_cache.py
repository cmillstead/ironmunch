"""Invalidate cache / delete index tool."""

from typing import Optional

from ..core.errors import sanitize_error, RepoNotFoundError
from ..core.validation import ValidationError
from ..parser.graph import CodeGraph
from ..storage import IndexStore
from ._common import parse_repo
from .registry import ToolSpec, register


def invalidate_cache(
    repo: str,
    storage_path: Optional[str] = None,
    confirm: bool = False,
) -> dict:
    """Delete an index and all cached data for a repository.

    This is an alias for delete_index that also ensures any in-memory
    state is cleared. Use when you want to force a full re-index.

    Args:
        repo: Repository identifier (owner/repo or just repo name).
        storage_path: Custom storage path.
        confirm: Must be True to permanently delete the index. Pass
            confirm=True to confirm you want to permanently delete this
            index. If False (the default), the call is rejected with a
            ValidationError.

    Returns:
        Dict with success status.
    """
    # --- ADV-MED-13: require explicit confirmation before deleting ---
    if not confirm:
        raise ValidationError("Pass confirm=True to permanently delete this index")

    # --- security gate: parse + validate repo identifier ---
    try:
        owner, name = parse_repo(repo, storage_path)
    except RepoNotFoundError as exc:
        return {"error": str(exc)}

    try:
        store = IndexStore(base_path=storage_path)
        # TODO(security): TOCTOU race — concurrent index_repo could write between our
        # existence check and delete. Full fix requires file-level locking.
        deleted = store.delete_index(owner, name)
    except Exception as exc:
        return {"error": sanitize_error(exc)}

    if deleted:
        # Clear the in-memory graph cache so stale graphs aren't reused
        CodeGraph.clear_cache()
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


_spec = register(ToolSpec(
    name="invalidate_cache",
    description=(
        "Delete the index and cached files for a repository. "
        "Forces a full re-index on next index_repo or index_folder call. "
        "Requires confirm=True to prevent accidental deletion."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "repo": {
                "type": "string",
                "description": "Repository identifier (owner/repo or just repo name)",
            },
            "confirm": {
                "type": "boolean",
                "description": (
                    "Must be true to permanently delete this index. "
                    "Pass confirm=True to confirm you want to permanently delete this index."
                ),
                "default": False,
            },
        },
        "required": ["repo"],
    },
    handler=lambda args, storage_path: invalidate_cache(
        repo=args["repo"],
        storage_path=storage_path,
        confirm=args.get("confirm", False),
    ),
    destructive=True,
    required_args=["repo"],
))
