"""Full-text search across indexed file contents.

**Security fix (issue #2):** Every file path from the index is validated
against the content directory before reading. This prevents path traversal
via crafted entries in the index's source_files list.
"""

import fnmatch
from typing import Optional

from ..security import validate_file_access, sanitize_signature_for_api, safe_read_file
from ..core.limits import MAX_SEARCH_RESULTS
from ..core.boundaries import wrap_untrusted_content, make_meta
from ..core.errors import RepoNotFoundError
from ..core.validation import ValidationError
from ..storage import IndexStore
from ._common import parse_repo, timed, elapsed_ms
from .registry import ToolSpec, register

_REDACTION_SENTINEL = "<REDACTED>"


def search_text(
    repo: str,
    query: str,
    file_pattern: Optional[str] = None,
    max_results: int = 20,
    confirm_sensitive_search: bool = False,
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
        confirm_sensitive_search: Must be True to acknowledge text-search risk.
        storage_path: Custom storage path.

    Returns:
        Dict with matching lines grouped by file, plus _meta envelope.
    """
    start = timed()

    if not confirm_sensitive_search:
        return {
            "error": (
                "search_text requires confirm_sensitive_search=True because "
                "full-text search can reveal indexed content."
            )
        }
    if query.strip().upper() == _REDACTION_SENTINEL:
        return {
            "error": "Query targets internal redaction markers and is not allowed"
        }

    # --- security gate: parse + validate repo identifier ---
    try:
        owner, name = parse_repo(repo, storage_path)
    except RepoNotFoundError as exc:
        return {"error": str(exc)}

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
            content = safe_read_file(validated, str(content_dir))
        except Exception:
            continue

        files_searched += 1
        lines = sanitize_signature_for_api(content).split("\n")
        for line_num, line in enumerate(lines, 1):
            if query_lower in line.lower():
                matches.append({
                    "file": wrap_untrusted_content(file_path),
                    "line": line_num,
                    # --- content boundary wrapping (SEC-LOW-5: scan 250-char window then truncate to 200) ---
                    "text": wrap_untrusted_content(sanitize_signature_for_api(line.rstrip()[:250])[:200]),
                })
                if len(matches) >= max_results:
                    break

        if len(matches) >= max_results:
            break

    ms = elapsed_ms(start)

    return {
        "repo": f"{owner}/{name}",
        "query": wrap_untrusted_content(sanitize_signature_for_api(query)),
        "result_count": len(matches),
        "results": matches,
        "_meta": {
            **make_meta(source="code_index", trusted=False),
            "timing_ms": ms,
            "files_searched": files_searched,
            "truncated": len(matches) >= max_results,
        },
    }


_spec = register(ToolSpec(
    name="search_text",
    description=(
        "Full-text search across indexed file contents. Useful when "
        "symbol search misses (e.g., string literals, comments, "
        "config values)."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "repo": {
                "type": "string",
                "description": "Repository identifier (owner/repo or just repo name)",
            },
            "query": {
                "type": "string",
                "description": "Text to search for (case-insensitive substring match)",
            },
            "file_pattern": {
                "type": "string",
                "description": "Optional glob pattern to filter files (e.g., '*.py')",
            },
            "max_results": {
                "type": "integer",
                "description": "Maximum number of matching lines to return",
                "default": 20,
            },
            "confirm_sensitive_search": {
                "type": "boolean",
                "description": "Must be true to acknowledge that full-text search can reveal indexed content.",
                "default": False,
            },
        },
        "required": ["repo", "query"],
    },
    handler=lambda args, storage_path: search_text(
        repo=args["repo"],
        query=args["query"],
        file_pattern=args.get("file_pattern"),
        max_results=args.get("max_results", 20),
        confirm_sensitive_search=args.get("confirm_sensitive_search", False),
        storage_path=storage_path,
    ),
    text_search=True,
    untrusted=True,
    required_args=["repo", "query"],
))
