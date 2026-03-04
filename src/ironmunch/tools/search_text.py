"""Full-text search across indexed file contents.

**Security fix (issue #2):** Every file path from the index is validated
against the content directory before reading. This prevents path traversal
via crafted entries in the index's source_files list.
"""

import fnmatch
import time
from pathlib import Path
from typing import Optional

from ..security import validate_file_access, sanitize_signature_for_api
from ..core.limits import MAX_SEARCH_RESULTS
from ..core.boundaries import wrap_untrusted_content, make_meta
from ..core.errors import sanitize_error
from ..core.validation import ValidationError
from ..storage import IndexStore
from ._common import parse_repo, timed, elapsed_ms


def search_text(
    repo: str,
    query: str,
    file_pattern: Optional[str] = None,
    max_results: int = 20,
    storage_path: Optional[str] = None,
) -> dict:
    """Search for text across all indexed files in a repository.

    Useful when symbol search misses -- e.g., searching for string literals,
    comments, configuration values, or patterns not captured as symbols.

    Args:
        repo: Repository identifier (owner/repo or just repo name).
        query: Text to search for (case-insensitive substring match).
        file_pattern: Optional glob pattern to filter files.
        max_results: Maximum number of matching lines to return.
        storage_path: Custom storage path.

    Returns:
        Dict with matching lines grouped by file, plus _meta envelope.
    """
    start = timed()

    # --- security gate: parse + validate repo identifier ---
    parsed = parse_repo(repo, storage_path)
    if isinstance(parsed, dict):
        return parsed
    owner, name = parsed

    store = IndexStore(base_path=storage_path)
    index = store.load_index(owner, name)

    if not index:
        return {"error": f"Repository not indexed: {owner}/{name}"}

    # Clamp max_results
    max_results = min(max(max_results, 1), MAX_SEARCH_RESULTS)

    # Filter files by pattern
    files = index.source_files
    if file_pattern:
        files = [
            f for f in files
            if fnmatch.fnmatch(f, file_pattern)
            or fnmatch.fnmatch(f, f"*/{file_pattern}")
        ]

    content_dir = str(store._content_dir(owner, name))
    query_lower = query.lower()
    matches = []
    files_searched = 0

    for file_path in files:
        # --- security gate: validate each file path from the index ---
        try:
            validated = validate_file_access(file_path, content_dir)
        except ValidationError:
            continue  # Skip files with unsafe paths

        try:
            content = Path(validated).read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        files_searched += 1
        lines = content.split("\n")
        for line_num, line in enumerate(lines, 1):
            if query_lower in line.lower():
                matches.append({
                    "file": file_path,
                    "line": line_num,
                    # --- content boundary wrapping (secret redaction before truncation) ---
                    "text": wrap_untrusted_content(sanitize_signature_for_api(line.rstrip())[:200]),
                })
                if len(matches) >= max_results:
                    break

        if len(matches) >= max_results:
            break

    ms = elapsed_ms(start)

    return {
        "repo": f"{owner}/{name}",
        "query": query,
        "result_count": len(matches),
        "results": matches,
        "_meta": {
            **make_meta(source="code_index", trusted=False),
            "timing_ms": ms,
            "files_searched": files_searched,
            "truncated": len(matches) >= max_results,
        },
    }
