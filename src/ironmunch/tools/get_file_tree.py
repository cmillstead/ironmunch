"""Get file tree for a repository."""

import os
import time
from typing import Optional

from ..core.boundaries import make_meta
from ..core.errors import sanitize_error
from ..storage import IndexStore
from ..parser import LANGUAGE_EXTENSIONS
from ._common import parse_repo, timed, elapsed_ms


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

    # --- security gate: parse + validate repo identifier ---
    parsed = parse_repo(repo, storage_path)
    if isinstance(parsed, dict):
        return parsed
    owner, name = parsed

    # --- security gate: validate path_prefix ---
    if "\x00" in path_prefix:
        return {"error": "path_prefix contains null bytes"}
    # Reject if any path component is a traversal sequence
    prefix_parts = path_prefix.replace("\\", "/").split("/")
    if any(part == ".." for part in prefix_parts):
        return {"error": "path_prefix must not contain '..' components"}

    store = IndexStore(base_path=storage_path)
    index = store.load_index(owner, name)

    if not index:
        return {"error": f"Repository not indexed: {owner}/{name}"}

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
            **make_meta(source="index_list", trusted=True),
            "timing_ms": ms,
            "file_count": len(files),
        },
    }


def _build_tree(files: list[str], index, path_prefix: str) -> list[dict]:
    """Build nested tree from flat file list."""
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
                # File node
                symbol_count = sum(1 for s in index.symbols if s.get("file") == file_path)

                _, ext = os.path.splitext(file_path)
                lang = LANGUAGE_EXTENSIONS.get(ext, "")

                current[part] = {
                    "path": file_path,
                    "type": "file",
                    "language": lang,
                    "symbol_count": symbol_count,
                }
            else:
                # Directory node
                if part not in current:
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
                "path": name + "/",
                "type": "dir",
                "children": _dict_to_list(node.get("children", {})),
            })

    return result
