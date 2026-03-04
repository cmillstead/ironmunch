"""Shared helpers for tool handlers.

Centralizes repo identifier parsing and validation so each tool
doesn't duplicate the logic.
"""

import time
from typing import Optional

from ..security import sanitize_repo_identifier
from ..storage import IndexStore
from ..core.errors import sanitize_error, RepoNotFoundError


def parse_repo(
    repo: str, storage_path: Optional[str] = None
) -> tuple[str, str]:
    """Parse a repo identifier into (owner, name).

    Accepts ``owner/repo`` or a bare ``repo`` name (resolved by
    searching existing indexes).

    Returns:
        Tuple ``(owner, name)`` on success.

    Raises:
        RepoNotFoundError: If the repository cannot be found or identified.
    """
    if "/" in repo:
        owner, name = repo.split("/", 1)
    else:
        store = IndexStore(base_path=storage_path)
        repos = store.list_repos()
        matching = [r for r in repos if r["repo"].endswith(f"/{repo}")]
        if not matching:
            raise RepoNotFoundError(f"Repository not found: {repo}")
        if len(matching) > 1:
            raise RepoNotFoundError("Ambiguous repository name. Use full owner/repo format (e.g., 'owner/myproject').")
        owner, name = matching[0]["repo"].split("/", 1)

    # Validate identifiers against injection
    try:
        sanitize_repo_identifier(owner)
        sanitize_repo_identifier(name)
    except Exception as exc:
        raise RepoNotFoundError(sanitize_error(exc)) from exc

    return owner, name


def timed() -> float:
    """Return a perf_counter timestamp for timing calculations."""
    return time.perf_counter()


def elapsed_ms(start: float) -> float:
    """Milliseconds since *start*."""
    return round((time.perf_counter() - start) * 1000, 1)


def calculate_symbol_score(sym: dict, query_lower: str, query_words: set) -> int:
    """Calculate search score for a symbol.

    Used by both ``search_symbols`` (tool layer) and ``CodeIndex.search``
    (storage layer) so the ranking logic stays in a single place.
    """
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
