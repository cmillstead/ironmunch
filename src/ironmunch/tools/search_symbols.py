"""Search symbols across a repository."""

import time
from typing import Optional

from ..core.limits import MAX_SEARCH_RESULTS
from ..core.boundaries import make_meta, wrap_untrusted_content
from ..core.errors import sanitize_error
from ..storage import IndexStore
from ._common import parse_repo, timed, elapsed_ms


def search_symbols(
    repo: str,
    query: str,
    kind: Optional[str] = None,
    file_pattern: Optional[str] = None,
    language: Optional[str] = None,
    max_results: int = 10,
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
        storage_path: Custom storage path.

    Returns:
        Dict with search results and _meta envelope.
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

    # Search
    results = index.search(query, kind=kind, file_pattern=file_pattern)

    # Apply language filter (post-search since CodeIndex.search doesn't support it)
    if language:
        results = [s for s in results if s.get("language") == language]

    # Score and sort (search already does this, but we need to add score to output)
    query_lower = query.lower()
    query_words = set(query_lower.split())

    scored_results = []
    for sym in results[:max_results]:
        score = _calculate_score(sym, query_lower, query_words)
        scored_results.append({
            "id": sym["id"],
            "kind": sym["kind"],
            "name": sym["name"],
            "file": sym["file"],
            "line": sym["line"],
            "signature": wrap_untrusted_content(sym["signature"]),
            "summary": wrap_untrusted_content(sym.get("summary", "")),
            "score": score,
        })

    ms = elapsed_ms(start)

    return {
        "repo": f"{owner}/{name}",
        "query": query,
        "result_count": len(scored_results),
        "results": scored_results,
        "_meta": {
            **make_meta(source="code_index", trusted=False),
            "timing_ms": ms,
            "total_symbols": len(index.symbols),
            "truncated": len(results) > max_results,
        },
    }


def _calculate_score(sym: dict, query_lower: str, query_words: set) -> int:
    """Calculate search score for a symbol."""
    score = 0

    # 1. Exact name match (highest weight)
    name_lower = sym.get("name", "").lower()
    if query_lower == name_lower:
        score += 20
    elif query_lower in name_lower:
        score += 10

    # 2. Name word overlap
    for word in query_words:
        if word in name_lower:
            score += 5

    # 3. Signature match
    sig_lower = sym.get("signature", "").lower()
    if query_lower in sig_lower:
        score += 8
    for word in query_words:
        if word in sig_lower:
            score += 2

    # 4. Summary match
    summary_lower = sym.get("summary", "").lower()
    if query_lower in summary_lower:
        score += 5
    for word in query_words:
        if word in summary_lower:
            score += 1

    # 5. Keyword match
    keywords = set(sym.get("keywords", []))
    matching_keywords = query_words & keywords
    score += len(matching_keywords) * 3

    # 6. Docstring match
    doc_lower = sym.get("docstring", "").lower()
    for word in query_words:
        if word in doc_lower:
            score += 1

    return score
