"""Get high-level repository outline."""

import os
from collections import Counter
from typing import Optional

from ..core.boundaries import make_meta
from ..core.errors import sanitize_error, RepoNotFoundError
from ..storage import IndexStore
from ._common import parse_repo, timed, elapsed_ms


def get_repo_outline(
    repo: str,
    storage_path: Optional[str] = None,
) -> dict:
    """Get a high-level overview of an indexed repository.

    Returns top-level directories, file counts, language breakdown,
    and total symbol count. Lighter than get_file_tree.

    Args:
        repo: Repository identifier (owner/repo or just repo name).
        storage_path: Custom storage path.

    Returns:
        Dict with repo outline and _meta envelope.
    """
    start = timed()

    # --- security gate: parse + validate repo identifier ---
    try:
        owner, name = parse_repo(repo, storage_path)
    except RepoNotFoundError as exc:
        return {"error": str(exc)}

    store = IndexStore(base_path=storage_path)
    index = store.load_index(owner, name)

    if not index:
        return {"error": f"Repository not indexed: {owner}/{name}"}

    # Compute directory-level stats
    dir_file_counts: Counter = Counter()
    for f in index.source_files:
        parts = f.split("/")
        if len(parts) > 1:
            dir_file_counts[parts[0] + "/"] += 1
        else:
            dir_file_counts["(root)"] += 1

    # Symbol kind breakdown
    kind_counts: Counter = Counter()
    for sym in index.symbols:
        kind_counts[sym.get("kind", "unknown")] += 1

    ms = elapsed_ms(start)

    return {
        "repo": f"{owner}/{name}",
        "indexed_at": index.indexed_at,
        "file_count": len(index.source_files),
        "symbol_count": len(index.symbols),
        "languages": index.languages,
        "directories": dict(dir_file_counts.most_common()),
        "symbol_kinds": dict(kind_counts.most_common()),
        "_meta": {
            **make_meta(source="index_list", trusted=True),
            "timing_ms": ms,
        },
    }
