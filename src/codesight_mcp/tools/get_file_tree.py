"""Get file tree for a repository."""

import os
from collections import Counter
from typing import Optional

from ..core.boundaries import make_meta, wrap_untrusted_content
from ..parser import LANGUAGE_EXTENSIONS
from ._common import RepoContext, timed, elapsed_ms
from mcp.types import ToolAnnotations
from .registry import ToolSpec, register


def get_file_tree(
    repo: str,
    path_prefix: str = "",
    storage_path: Optional[str] = None,
) -> dict:
    """Get repository file tree, optionally filtered by path prefix.

    Args:
        repo: Repository identifier (owner/repo or just repo name).
        path_prefix: Optional path prefix to filter.
        storage_path: Custom storage path.

    Returns:
        Dict with hierarchical tree structure and _meta envelope.
    """
    start = timed()

    # --- security gate: validate path_prefix ---
    if "\x00" in path_prefix:
        return {"error": "path_prefix contains null bytes"}
    # Reject if any path component is a traversal sequence
    prefix_parts = path_prefix.replace("\\", "/").split("/")
    if any(part == ".." for part in prefix_parts):
        return {"error": "path_prefix must not contain '..' components"}

    ctx = RepoContext.resolve(repo, storage_path)
    if isinstance(ctx, dict):
        return ctx
    owner, name, index = ctx.owner, ctx.name, ctx.index

    # Filter files by prefix
    files = [f for f in index.source_files if f.startswith(path_prefix)]

    if not files:
        return {
            "repo": f"{owner}/{name}",
            "path_prefix": path_prefix,
            "tree": [],
        }

    # Build tree structure
    tree = _build_tree(files, index, path_prefix)

    ms = elapsed_ms(start)

    return {
        "repo": f"{owner}/{name}",
        "path_prefix": path_prefix,
        "tree": tree,
        "_meta": {
            **make_meta(source="index_list", trusted=False),
            "timing_ms": ms,
            "file_count": len(files),
        },
    }


def _build_tree(files: list[str], index, path_prefix: str) -> list[dict]:
    """Build nested tree from flat file list."""
    symbol_counts: Counter = Counter(s.get("file") for s in index.symbols)
    root: dict = {}

    for file_path in files:
        # Remove prefix for relative path
        rel_path = file_path[len(path_prefix):].lstrip("/")
        parts = rel_path.split("/")

        # Navigate/create tree
        current = root
        for i, part in enumerate(parts):
            is_last = i == len(parts) - 1

            if is_last:
                # File node — don't overwrite a directory node that has children
                existing = current.get(part)
                if existing and existing.get("type") == "dir" and existing.get("children"):
                    continue

                symbol_count = symbol_counts[file_path]

                _, ext = os.path.splitext(file_path)
                lang = LANGUAGE_EXTENSIONS.get(ext, "")

                current[part] = {
                    "path": wrap_untrusted_content(file_path),
                    "type": "file",
                    "language": lang,
                    "symbol_count": symbol_count,
                }
            else:
                # Directory node — don't overwrite a file node; prefer dir (has children)
                existing = current.get(part)
                if existing and existing.get("type") == "file":
                    current[part] = {"type": "dir", "children": {}, "symbol_count": existing.get("symbol_count", 0)}
                elif part not in current:
                    current[part] = {"type": "dir", "children": {}}
                current = current[part]["children"]

    return _dict_to_list(root)


def _dict_to_list(node_dict: dict) -> list[dict]:
    """Convert tree dict to list format."""
    result = []

    for name, node in sorted(node_dict.items()):
        if node.get("type") == "file":
            result.append(node)
        else:
            result.append({
                "path": wrap_untrusted_content(name + "/"),
                "type": "dir",
                "children": _dict_to_list(node.get("children", {})),
            })

    return result


_spec = register(ToolSpec(
    name="get_file_tree",
    description="Get the file tree of an indexed repository, optionally filtered by path prefix.",
    input_schema={
        "type": "object",
        "properties": {
            "repo": {
                "type": "string",
                "description": "Repository identifier (owner/repo or just repo name)",
            },
            "path_prefix": {
                "type": "string",
                "description": "Optional path prefix to filter (e.g., 'src/utils')",
                "default": "",
            },
        },
        "required": ["repo"],
    },
    handler=lambda args, storage_path: get_file_tree(
        repo=args["repo"],
        path_prefix=args.get("path_prefix", ""),
        storage_path=storage_path,
    ),
    required_args=["repo"],
    annotations=ToolAnnotations(title="Get File Tree", readOnlyHint=True, openWorldHint=False),
))
