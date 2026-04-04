"""Compare symbols between two indexed repos using content hashes."""

from typing import Optional

from ..core.boundaries import make_meta, wrap_untrusted_content
from ..security import sanitize_signature_for_api
from ._common import RepoContext, timed, elapsed_ms
from mcp.types import ToolAnnotations
from .registry import ToolSpec, register


def compare_symbols(
    base_repo: str,
    head_repo: str,
    storage_path: Optional[str] = None,
) -> dict:
    """Compare symbols between two indexed repos using content hashes.

    Detects added, removed, and modified symbols by comparing symbol IDs
    and content hashes. Pure index operation -- no git or text diffing needed.

    Args:
        base_repo: Base repository identifier (owner/repo or just repo name).
        head_repo: Head repository identifier to compare against base.
        storage_path: Custom storage path.

    Returns:
        Dict with added/removed/modified symbol lists, summary counts, and _meta.
    """
    start = timed()

    base_ctx = RepoContext.resolve(base_repo, storage_path)
    if isinstance(base_ctx, dict):
        return base_ctx

    head_ctx = RepoContext.resolve(head_repo, storage_path)
    if isinstance(head_ctx, dict):
        return head_ctx

    base_owner, base_name, base_index = base_ctx.owner, base_ctx.name, base_ctx.index
    head_owner, head_name, head_index = head_ctx.owner, head_ctx.name, head_ctx.index

    # Build symbol maps: {id: symbol_dict}
    base_map: dict[str, dict] = {sym["id"]: sym for sym in base_index.symbols if sym.get("id")}
    head_map: dict[str, dict] = {sym["id"]: sym for sym in head_index.symbols if sym.get("id")}

    base_ids = set(base_map.keys())
    head_ids = set(head_map.keys())

    added_ids = head_ids - base_ids
    removed_ids = base_ids - head_ids
    common_ids = base_ids & head_ids

    # Classify common symbols as modified or unchanged
    modified_ids = {
        sid for sid in common_ids
        if base_map[sid].get("content_hash") != head_map[sid].get("content_hash")
    }
    unchanged_count = len(common_ids) - len(modified_ids)

    # Build output lists
    added = []
    for sid in sorted(added_ids):
        sym = head_map[sid]
        added.append({
            "id": wrap_untrusted_content(sym.get("id", "")),
            "name": wrap_untrusted_content(sym.get("name", "")),
            "kind": sym.get("kind", ""),
            "file": wrap_untrusted_content(sym.get("file", "")),
            "signature": wrap_untrusted_content(
                sanitize_signature_for_api(sym.get("signature", ""))
            ),
        })

    removed = []
    for sid in sorted(removed_ids):
        sym = base_map[sid]
        removed.append({
            "id": wrap_untrusted_content(sym.get("id", "")),
            "name": wrap_untrusted_content(sym.get("name", "")),
            "kind": sym.get("kind", ""),
            "file": wrap_untrusted_content(sym.get("file", "")),
            "signature": wrap_untrusted_content(
                sanitize_signature_for_api(sym.get("signature", ""))
            ),
        })

    modified = []
    for sid in sorted(modified_ids):
        base_sym = base_map[sid]
        head_sym = head_map[sid]
        modified.append({
            "id": wrap_untrusted_content(base_sym.get("id", "")),
            "name": wrap_untrusted_content(base_sym.get("name", "")),
            "kind": base_sym.get("kind", ""),
            "file": wrap_untrusted_content(base_sym.get("file", "")),
            "base_signature": wrap_untrusted_content(
                sanitize_signature_for_api(base_sym.get("signature", ""))
            ),
            "head_signature": wrap_untrusted_content(
                sanitize_signature_for_api(head_sym.get("signature", ""))
            ),
        })

    ms = elapsed_ms(start)

    return {
        "base_repo": f"{base_owner}/{base_name}",
        "head_repo": f"{head_owner}/{head_name}",
        "added": added,
        "removed": removed,
        "modified": modified,
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "modified": len(modified),
            "unchanged": unchanged_count,
        },
        "_meta": {
            **make_meta(source="code_index", trusted=False),
            "timing_ms": ms,
        },
    }


_spec = register(ToolSpec(
    name="compare_symbols",
    description=(
        "Compare symbols between two indexed repositories using content hashes. "
        "Shows added, removed, and modified symbols. "
        "Pure index operation -- no git or text diffing needed."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "base_repo": {
                "type": "string",
                "description": "Base repository identifier (owner/repo or just repo name)",
            },
            "head_repo": {
                "type": "string",
                "description": "Head repository identifier to compare against base",
            },
            "storage_path": {
                "type": "string",
                "description": "Custom storage path (optional)",
            },
        },
        "required": ["base_repo", "head_repo"],
    },
    handler=lambda args, storage_path: compare_symbols(
        base_repo=args["base_repo"],
        head_repo=args["head_repo"],
        storage_path=storage_path,
    ),
    untrusted=True,
    required_args=["base_repo", "head_repo"],
    annotations=ToolAnnotations(title="Compare Symbols", readOnlyHint=True, openWorldHint=False),
))
