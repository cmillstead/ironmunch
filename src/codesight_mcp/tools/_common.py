"""Shared helpers for tool handlers.

Centralizes repo identifier parsing and validation so each tool
doesn't duplicate the logic.
"""

import time
from dataclasses import dataclass
from typing import Optional, Union

from ..security import sanitize_repo_identifier
from ..storage import CodeIndex, IndexStore
from ..core.errors import sanitize_error, RepoNotFoundError
from ..parser.graph import CodeGraph


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
        import re

        store = IndexStore(base_path=storage_path)
        try:
            repos = store.list_repos()
        except Exception as exc:
            raise RepoNotFoundError(f"Failed to list repositories: {exc}")
        # 1. Exact name match (e.g. "myproject" matches "acme/myproject")
        matching = [r for r in repos if r["repo"].endswith(f"/{repo}")]
        # 2. Prefix match for local hash-suffixed repos
        #    (e.g. "codesight-mcp" matches "local/codesight-mcp-b1d9a2d53f7f")
        if not matching:
            _hash_suffix = re.compile(r"^(.+)-[0-9a-f]{12}$")
            matching = []
            for r in repos:
                repo_name = r["repo"].rsplit("/", 1)[-1]
                m = _hash_suffix.match(repo_name)
                if m and m.group(1) == repo:
                    matching.append(r)

        if not matching:
            raise RepoNotFoundError(f"Repository not found: {repo}")
        if len(matching) > 1:
            raise RepoNotFoundError("Ambiguous repository name. Use full owner/repo format (e.g., 'owner/myproject').")
        repo_field = matching[0]["repo"]
        if "/" not in repo_field:
            raise RepoNotFoundError("Malformed repository identifier in index")
        owner, name = repo_field.split("/", 1)

    # Validate identifiers against injection
    try:
        sanitize_repo_identifier(owner)
        sanitize_repo_identifier(name)
    except Exception as exc:
        raise RepoNotFoundError(sanitize_error(exc)) from exc

    return owner, name


@dataclass
class RepoContext:
    """Resolved repository context -- shared by all tool handlers."""

    owner: str
    name: str
    store: IndexStore
    index: CodeIndex

    @classmethod
    def resolve(
        cls, repo: str, storage_path: Optional[str] = None
    ) -> Union["RepoContext", dict]:
        """Parse repo, load index, return context or error dict."""
        try:
            owner, name = parse_repo(repo, storage_path)
        except RepoNotFoundError as exc:
            return {"error": str(exc)}
        store = IndexStore(base_path=storage_path)
        index = store.load_index(owner, name)
        if not index:
            return {"error": f"Repository not indexed: {owner}/{name}"}
        return cls(owner=owner, name=name, store=store, index=index)


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


def prepare_graph_query(
    repo: str,
    symbol_id: Optional[str] = None,
    storage_path: Optional[str] = None,
) -> Union[tuple, dict]:
    """Shared setup for graph-based tool handlers.

    Performs the common boilerplate shared by all graph tools:
    1. Parse and validate the repo identifier.
    2. Load the index from storage.
    3. Optionally verify that a symbol exists in the index.
    4. Build (or retrieve cached) CodeGraph.

    Args:
        repo: Repository identifier (owner/repo or just repo name).
        symbol_id: Symbol ID to look up.  Pass ``None`` to skip
            the symbol-existence check (e.g. for file-based queries).
        storage_path: Custom storage path forwarded to IndexStore.

    Returns:
        On success a 5-tuple ``(owner, name, index, graph, symbol_info)``
        where *symbol_info* is the symbol dict when *symbol_id* was
        provided, or ``None`` otherwise.

        On failure a plain ``dict`` with an ``"error"`` key that the
        caller should return directly.
    """
    ctx = RepoContext.resolve(repo, storage_path)
    if isinstance(ctx, dict):
        return ctx

    owner, name, index = ctx.owner, ctx.name, ctx.index

    # Verify target symbol exists (when requested)
    symbol_info = None
    if symbol_id is not None:
        symbol_info = index.get_symbol(symbol_id)
        if not symbol_info:
            return {"error": f"Symbol not found: {symbol_id}"}

    # Build graph from index
    try:
        graph = CodeGraph.get_or_build(index.symbols)
    except Exception:
        return {"error": "Failed to build code graph"}

    return (owner, name, index, graph, symbol_info)
