"""Shared helpers for tool handlers.

Centralizes repo identifier parsing and validation so each tool
doesn't duplicate the logic.
"""

import re
import threading
import time
from dataclasses import dataclass
from typing import Optional, Union

from ..security import sanitize_repo_identifier
from ..storage import CodeIndex, IndexStore
from ..core.errors import sanitize_error, RepoNotFoundError
from ..core.validation import ValidationError
from ..parser.graph import CodeGraph

# Shared IndexStore instances keyed by storage_path.
# Reusing instances preserves the in-memory LRU cache across tool calls,
# eliminating repeated gzip decompress + JSON parse (~133 ms per call).
_store_instances: dict[str | None, IndexStore] = {}
_store_lock = threading.Lock()


def _get_shared_store(storage_path: str | None = None) -> IndexStore:
    """Return a shared IndexStore for *storage_path*, creating one if needed."""
    with _store_lock:
        if storage_path not in _store_instances:
            _store_instances[storage_path] = IndexStore(base_path=storage_path)
        return _store_instances[storage_path]


def _clear_shared_stores() -> None:
    """Clear the shared store cache (for testing only)."""
    with _store_lock:
        _store_instances.clear()


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

        store = _get_shared_store(storage_path)
        try:
            repos = store.list_repos()
        except (OSError, ValueError) as exc:
            raise RepoNotFoundError(f"Failed to list repositories: {exc}") from exc
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
    except (ValueError, ValidationError) as exc:
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
        store = _get_shared_store(storage_path)
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


_CAMEL_RE = re.compile(r'(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])')
_SEPARATOR_RE = re.compile(r'[_\-\s]+')


def _split_identifier(name: str) -> set[str]:
    """Split camelCase, PascalCase, snake_case into a set of lowercase words."""
    parts = _SEPARATOR_RE.split(name)
    words = set()
    for part in parts:
        if not part:
            continue
        subparts = _CAMEL_RE.split(part)
        for sp in subparts:
            if sp:
                words.add(sp.lower())
    return words


# Simple suffix-stripping stemmer (no external dependencies).
# Each rule is (suffix, min_stem_len, replacement).
# Order matters -- longer suffixes first to avoid partial stripping.
_SUFFIX_RULES: list[tuple[str, int, str]] = [
    ("ation", 3, "ate"),
    ("ating", 3, "ate"),
    ("ment", 3, ""),
    ("ness", 3, ""),
    ("ible", 3, ""),
    ("able", 3, ""),
    ("ence", 3, ""),
    ("ance", 3, ""),
    ("less", 3, ""),
    ("ful", 3, ""),
    ("ous", 3, ""),
    ("ive", 3, ""),
    ("ity", 3, ""),
    ("ing", 3, ""),
    ("ly", 3, ""),
    ("er", 3, "e"),
    ("ed", 3, "e"),
    ("es", 3, ""),
    ("al", 3, ""),
    ("s", 3, ""),
]


def _stem(word: str) -> str:
    """Simple suffix-stripping stemmer. No external dependencies."""
    word = word.lower()
    if len(word) <= 3:
        return word
    for suffix, min_len, replacement in _SUFFIX_RULES:
        if word.endswith(suffix) and len(word) - len(suffix) >= min_len:
            stem = word[:-len(suffix)] + replacement
            # Avoid stems ending with duplicate trailing char from replacement
            # e.g. "parsee" from "parser" -> "pars" + "e" is fine, but
            # "parseed" would not happen with our rules.
            return stem
    return word


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

    # 7. Normalized token matching (compound splitting + stemming)
    query_stems = {_stem(w) for w in query_words}

    name_tokens = _split_identifier(sym.get("name", ""))
    name_stems = {_stem(t) for t in name_tokens}
    score += len(query_stems & name_stems) * 4

    sig_words = set(sym.get("signature", "").lower().split())
    sig_tokens = set()
    for w in sig_words:
        sig_tokens.update(_split_identifier(w))
    sig_stems = {_stem(t) for t in sig_tokens}
    score += len(query_stems & sig_stems) * 1

    summary_words = set(sym.get("summary", "").lower().split())
    summary_stems = {_stem(w) for w in summary_words}
    score += len(query_stems & summary_stems) * 2

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
    except (ValueError, TypeError, KeyError):
        return {"error": "Failed to build code graph"}

    return (owner, name, index, graph, symbol_info)
