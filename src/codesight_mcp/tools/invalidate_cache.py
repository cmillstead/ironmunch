"""Invalidate cache / delete index tool."""

from typing import Optional

from ..core.errors import sanitize_error, RepoNotFoundError
from ..parser.graph import CodeGraph
from ._common import parse_repo, _get_shared_store
from .registry import ToolSpec, register
from mcp.types import ToolAnnotations


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
        return {"error": "Pass confirm=True to permanently delete this index"}

    # --- security gate: parse + validate repo identifier ---
    try:
        owner, name = parse_repo(repo, storage_path)
    except RepoNotFoundError as exc:
        return {"error": str(exc)}

    try:
        store = _get_shared_store(storage_path)
        # TODO(security): TOCTOU race — concurrent index_repo could write between our
        # existence check and delete. Full fix requires file-level locking.
        deleted = store.delete_index(owner, name)
    except OSError as exc:
        return {"error": sanitize_error(exc)}

    if deleted:
        # Clear the in-memory graph cache so stale graphs aren't reused
        CodeGraph.clear_cache()
        # Also remove embedding sidecar so stale vectors don't survive
        try:
            from ..embeddings.store import EmbeddingStore
            embed_store = EmbeddingStore(owner, name, storage_path)
            sidecar = embed_store._path
            if sidecar.exists():
                sidecar.unlink()
        except Exception:
            pass  # best-effort — don't fail cache invalidation for embedding cleanup
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
    annotations=ToolAnnotations(title="Delete Repository Index", readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=False),
))
