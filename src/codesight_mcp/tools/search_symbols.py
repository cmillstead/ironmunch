"""Search symbols across a repository."""

from typing import Optional

from ..core.limits import MAX_SEARCH_RESULTS
from ..core.boundaries import make_meta, wrap_untrusted_content
from ..core.errors import sanitize_error, RepoNotFoundError
from ..parser.extractor import SUPPORTED_LANGUAGES
from ..security import sanitize_signature_for_api
from ._common import RepoContext, timed, elapsed_ms, calculate_symbol_score
from .registry import ToolSpec, register

_MAX_CROSS_REPO = 5


def _search_single_repo(
    repo: str,
    query: str,
    kind: Optional[str],
    file_pattern: Optional[str],
    language: Optional[str],
    max_results: int,
    storage_path: Optional[str],
) -> dict:
    """Search symbols in a single repo. Returns result dict."""
    ctx = RepoContext.resolve(repo, storage_path)
    if isinstance(ctx, dict):
        return ctx
    owner, name, index = ctx.owner, ctx.name, ctx.index

    results = index.search(query, kind=kind, file_pattern=file_pattern)

    if language:
        results = [s for s in results if s.get("language") == language]

    query_lower = query.lower()
    query_words = set(query_lower.split())

    scored_results = []
    for sym in results[:max_results]:
        score = calculate_symbol_score(sym, query_lower, query_words)
        scored_results.append({
            "id": wrap_untrusted_content(sym["id"]),
            "kind": sym["kind"],
            "name": wrap_untrusted_content(sym["name"]),
            "file": wrap_untrusted_content(sym["file"]),
            "line": sym["line"],
            "signature": wrap_untrusted_content(sym["signature"]),
            "summary": wrap_untrusted_content(sym.get("summary", "")),
            "score": round(score, 1),
            "repo": f"{owner}/{name}",
        })

    return {
        "repo": f"{owner}/{name}",
        "results": scored_results,
        "total_symbols": len(index.symbols),
        "all_results_count": len(results),
    }


def search_symbols(
    repo: Optional[str] = None,
    query: str = "",
    kind: Optional[str] = None,
    file_pattern: Optional[str] = None,
    language: Optional[str] = None,
    max_results: int = 10,
    repos: Optional[list[str]] = None,
    storage_path: Optional[str] = None,
) -> dict:
    """Search for symbols matching a query.

    Args:
        repo: Repository identifier (owner/repo or just repo name).
        query: Search query.
        kind: Optional filter by symbol kind.
        file_pattern: Optional glob pattern to filter files.
        language: Optional filter by language (e.g., "python", "javascript").
        max_results: Maximum results to return.
        repos: Optional list of repo identifiers to search across (max 5).
               Mutually exclusive with repo.
        storage_path: Custom storage path.

    Returns:
        Dict with search results and _meta envelope.
    """
    if not isinstance(query, str) or not query.strip():
        return {"error": "query must be a non-empty string"}

    # --- security gate: validate kind and language allowlists ---
    _VALID_KINDS = {"function", "class", "method", "constant", "type"}
    _VALID_LANGUAGES = SUPPORTED_LANGUAGES

    if kind is not None and kind not in _VALID_KINDS:
        return {
            "error": f"Invalid kind: {kind!r}. Must be one of: {sorted(_VALID_KINDS)}",
            "result_count": 0,
            "results": [],
        }

    if language is not None and language not in _VALID_LANGUAGES:
        return {
            "error": f"Invalid language: {language!r}. Must be one of: {sorted(_VALID_LANGUAGES)}",
            "result_count": 0,
            "results": [],
        }

    # Determine which repos to search
    if repos and repo:
        return {"error": "Cannot specify both 'repo' and 'repos'", "result_count": 0, "results": []}
    if not repos and not repo:
        return {"error": "Must specify either 'repo' or 'repos'", "result_count": 0, "results": []}

    repo_list = repos if repos else [repo]
    if len(repo_list) > _MAX_CROSS_REPO:
        return {
            "error": f"Too many repos: {len(repo_list)} exceeds maximum of {_MAX_CROSS_REPO}",
            "result_count": 0,
            "results": [],
        }

    start = timed()

    # Clamp max_results
    max_results = min(max(max_results, 1), MAX_SEARCH_RESULTS)

    # Search across all repos
    all_scored = []
    total_symbols = 0
    truncated = False
    errors = []
    repos_searched = []

    for r in repo_list:
        result = _search_single_repo(r, query, kind, file_pattern, language, max_results, storage_path)
        if "error" in result:
            errors.append({"repo": r, "error": result["error"]})
            continue
        repos_searched.append(result["repo"])
        all_scored.extend(result["results"])
        total_symbols += result["total_symbols"]
        if result["all_results_count"] > max_results:
            truncated = True

    # Sort merged results by score descending, take top max_results
    all_scored.sort(key=lambda x: x["score"], reverse=True)
    final_results = all_scored[:max_results]
    if len(all_scored) > max_results:
        truncated = True

    ms = elapsed_ms(start)

    # Build response
    is_multi = len(repo_list) > 1
    response: dict = {
        "query": wrap_untrusted_content(sanitize_signature_for_api(query)),
        "result_count": len(final_results),
        "results": final_results,
        "_meta": {
            **make_meta(source="code_index", trusted=False),
            "timing_ms": ms,
            "total_symbols": total_symbols,
            "truncated": truncated,
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
    name="search_symbols",
    description=(
        "Search for symbols matching a query across one or more "
        "indexed repositories. Returns matches with signatures and "
        "summaries. Use 'repo' for a single repo or 'repos' for cross-repo search (max 5)."
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
                "description": "Search query (matches symbol names, signatures, summaries, docstrings)",
            },
            "repos": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of repository identifiers to search across (max 5). Mutually exclusive with 'repo'.",
                "maxItems": 5,
            },
            "kind": {
                "type": "string",
                "description": "Optional filter by symbol kind",
                "enum": ["function", "class", "method", "constant", "type"],
            },
            "file_pattern": {
                "type": "string",
                "description": "Optional glob pattern to filter files (e.g., 'src/**/*.py')",
            },
            "language": {
                "type": "string",
                "description": "Optional filter by language",
                "enum": sorted(SUPPORTED_LANGUAGES),
            },
            "max_results": {
                "type": "integer",
                "description": "Maximum number of results to return",
                "default": 10,
            },
        },
        "required": ["query"],
    },
    handler=lambda args, storage_path: search_symbols(
        repo=args.get("repo"),
        query=args["query"],
        kind=args.get("kind"),
        file_pattern=args.get("file_pattern"),
        language=args.get("language"),
        max_results=args.get("max_results", 10),
        repos=args.get("repos"),
        storage_path=storage_path,
    ),
    untrusted=True,
    required_args=["query"],
))
