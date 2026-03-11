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
from ._common import RepoContext, timed, elapsed_ms
from .registry import ToolSpec, register

_REDACTION_SENTINEL = "<REDACTED>"
_MAX_CROSS_REPO = 5


def _search_text_single_repo(
    repo: str,
    query: str,
    query_lower: str,
    file_pattern: Optional[str],
    max_results: int,
    storage_path: Optional[str],
    repo_label: bool = False,
) -> dict:
    """Search text in a single repo. Returns result dict or error dict."""
    ctx = RepoContext.resolve(repo, storage_path)
    if isinstance(ctx, dict):
        return ctx
    owner, name, store, index = ctx.owner, ctx.name, ctx.store, ctx.index

    files = index.source_files
    if file_pattern:
        files = [
            f for f in files
            if fnmatch.fnmatch(f, file_pattern)
            or fnmatch.fnmatch(f, f"*/{file_pattern}")
        ]

    content_dir = str(store._content_dir(owner, name))
    matches = []
    files_searched = 0

    for file_path in files:
        try:
            validated = validate_file_access(file_path, content_dir)
        except ValidationError:
            continue

        try:
            content = safe_read_file(validated, str(content_dir))
        except Exception:
            continue

        files_searched += 1
        lines = sanitize_signature_for_api(content).split("\n")
        for line_num, line in enumerate(lines, 1):
            if query_lower in line.lower():
                match: dict = {
                    "file": wrap_untrusted_content(file_path),
                    "line": line_num,
                    "text": wrap_untrusted_content(sanitize_signature_for_api(line.rstrip()[:250])[:200]),
                }
                if repo_label:
                    match["repo"] = f"{owner}/{name}"
                matches.append(match)
                if len(matches) >= max_results:
                    break

        if len(matches) >= max_results:
            break

    return {
        "repo": f"{owner}/{name}",
        "results": matches,
        "files_searched": files_searched,
    }


def search_text(
    repo: Optional[str] = None,
    query: str = "",
    file_pattern: Optional[str] = None,
    max_results: int = 20,
    confirm_sensitive_search: bool = False,
    repos: Optional[list[str]] = None,
    storage_path: Optional[str] = None,
) -> dict:
    """Search for text across all indexed files in one or more repositories.

    Useful when symbol search misses -- e.g., searching for string literals,
    comments, configuration values, or patterns not captured as symbols.

    Args:
        repo: Repository identifier (owner/repo or just repo name).
        query: Text to search for (case-insensitive substring match).
        file_pattern: Optional glob pattern to filter files.
        max_results: Maximum number of matching lines to return.
        confirm_sensitive_search: Must be True to acknowledge text-search risk.
        repos: Optional list of repo identifiers to search across (max 5).
               Mutually exclusive with repo.
        storage_path: Custom storage path.

    Returns:
        Dict with matching lines grouped by file, plus _meta envelope.
    """
    start = timed()

    if not isinstance(query, str) or not query.strip():
        return {"error": "query must be a non-empty string"}

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

    # Determine which repos to search
    if repos and repo:
        return {"error": "Cannot specify both 'repo' and 'repos'"}
    if not repos and not repo:
        return {"error": "Must specify either 'repo' or 'repos'"}

    repo_list = repos if repos else [repo]
    if len(repo_list) > _MAX_CROSS_REPO:
        return {"error": f"Too many repos: {len(repo_list)} exceeds maximum of {_MAX_CROSS_REPO}"}

    # Clamp max_results
    max_results = min(max(max_results, 1), MAX_SEARCH_RESULTS)

    is_multi = len(repo_list) > 1
    query_lower = query.lower()
    all_matches = []
    total_files_searched = 0
    errors = []
    repos_searched = []

    for r in repo_list:
        remaining = max_results - len(all_matches)
        if remaining <= 0:
            break
        result = _search_text_single_repo(
            r, query, query_lower, file_pattern, remaining, storage_path,
            repo_label=is_multi,
        )
        if "error" in result:
            errors.append({"repo": r, "error": result["error"]})
            continue
        repos_searched.append(result["repo"])
        all_matches.extend(result["results"])
        total_files_searched += result["files_searched"]

    ms = elapsed_ms(start)

    response: dict = {
        "query": wrap_untrusted_content(sanitize_signature_for_api(query)),
        "result_count": len(all_matches),
        "results": all_matches,
        "_meta": {
            **make_meta(source="code_index", trusted=False),
            "timing_ms": ms,
            "files_searched": total_files_searched,
            "truncated": len(all_matches) >= max_results,
        },
    }

    if is_multi:
        response["repos"] = repos_searched
        if errors:
            response["errors"] = errors
    else:
        # Single-repo mode: if the repo failed, return the error directly
        if errors and not repos_searched:
            return {"error": errors[0]["error"]}
        response["repo"] = repos_searched[0] if repos_searched else repo_list[0]

    return response


_spec = register(ToolSpec(
    name="search_text",
    description=(
        "Full-text search across indexed file contents in one or more "
        "repositories. Useful when symbol search misses (e.g., string "
        "literals, comments, config values). Use 'repo' for a single "
        "repo or 'repos' for cross-repo search (max 5)."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "repo": {
                "type": "string",
                "description": "Repository identifier (owner/repo or just repo name). Mutually exclusive with 'repos'.",
            },
            "query": {
                "type": "string",
                "description": "Text to search for (case-insensitive substring match)",
            },
            "repos": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of repository identifiers to search across (max 5). Mutually exclusive with 'repo'.",
                "maxItems": 5,
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
        "required": ["query"],
    },
    handler=lambda args, storage_path: search_text(
        repo=args.get("repo"),
        query=args["query"],
        file_pattern=args.get("file_pattern"),
        max_results=args.get("max_results", 20),
        confirm_sensitive_search=args.get("confirm_sensitive_search", False),
        repos=args.get("repos"),
        storage_path=storage_path,
    ),
    text_search=True,
    untrusted=True,
    required_args=["query"],
))
