"""Shared helpers for tool handlers.

Centralizes repo identifier parsing and validation so each tool
doesn't duplicate the logic.
"""

import logging
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union

from ..security import sanitize_repo_identifier
from ..storage import CodeIndex, IndexStore
from ..core.boundaries import make_meta
from ..core.errors import sanitize_error, RepoNotFoundError
from ..core.freshness import age_threshold_exceeded
from ..core.validation import ValidationError
from ..parser.graph import CodeGraph

logger = logging.getLogger(__name__)

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


def _run_ondemand_index(path: str, storage_path: Optional[str] = None) -> dict:
    """Fast synchronous reindex of *path* via the existing index_folder handler.

    Routes through ``_handle_index_folder`` (lazy-imported to avoid the
    ``_common`` <-> ``index_folder`` import cycle) so the allowlist
    default-deny gate, ``O_NOFOLLOW``, every cap, the sanitizers, and the
    exclusive file lock are reused unchanged -- security stays monotonic.
    ``use_ai_summaries=False`` keeps it fast and off the network by default.

    Never raises; always returns the handler's result dict (or a sanitized
    failure dict) so a read op can never crash on an indexing error.
    """
    try:
        from .index_folder import _handle_index_folder
        return _handle_index_folder(
            {"path": path, "use_ai_summaries": False},
            storage_path,
        )
    except Exception as exc:  # RC-011: outer boundary -- indexing must never crash a read
        logger.debug("on-demand index failed for %s: %s", path, exc)
        return {"success": False, "error": sanitize_error(exc)}


@dataclass
class RepoContext:
    """Resolved repository context -- shared by all tool handlers."""

    owner: str
    name: str
    store: IndexStore
    index: CodeIndex
    freshly_indexed: bool = False
    stale: bool = False
    index_warnings: list = field(default_factory=list)

    @classmethod
    def resolve(
        cls, repo: str, storage_path: Optional[str] = None, *, path: Optional[str] = None
    ) -> Union["RepoContext", dict]:
        """Parse repo, load index, return context or error dict.

        When *path* is supplied and the resolved index is missing or stale
        (age strictly exceeds ``INDEX_AGE_THRESHOLD_DAYS``), the folder is
        indexed on demand through the existing validated pipeline
        (:func:`_run_ondemand_index`) and the freshly-built index is served
        with ``freshly_indexed=True``.

        Fails safe to today's behavior on any doubt (CLAUDE.md rules 4 & 8):

        - no path + missing index -> the existing "not indexed"/"not found" error
        - no path + stale index   -> serve the stale index with ``stale=True``
        - path + index failure    -> serve stale if present, else the sanitized
          index error, else the original error
        - path + success but reload empty -> the original error

        An unparseable/future ``indexed_at`` is treated as stale (fail-closed).

        Identity resolution follows the C28 dual-resolution policy -- each
        question is routed to its own input so a supplied ``path`` can never
        silently serve (or index) a repo the caller did not point at:

        - ``path`` supplied AND ``repo`` is a bare name (no ``/``) AND the
          resolved path's basename equals ``repo`` -> the PATH is authoritative
          for the whole resolve (identity, load, stale-check, on-demand index,
          serve). "The folder you point at" wins over a coincidentally
          same-named existing index (Finding 1a).
        - ``path`` supplied but its basename does NOT match a bare ``repo``
          name (e.g. a front-door auto-injecting cwd for a different repo) ->
          ``path`` is IGNORED for identity and the unrelated folder is never
          indexed; ``repo`` resolves normally (Finding 1b, cwd-injection guard).
        - ``repo`` is explicit ``owner/name`` -> ``path`` is ignored for
          identity; on-demand reindex is still allowed, gated by the
          directory-swap guard (the path must hash-match the resolved identity).

        A malformed/unresolvable ``path`` never raises out of resolve: it
        degrades to normal name resolution and the stale/error fallback
        (Finding 3; CLAUDE.md rules 4 & 8).
        """
        from .index_folder import folder_repo_identity

        store = _get_shared_store(storage_path)

        # --- C28: decide whether the supplied path owns the identity. ---
        # A bad path (e.g. embedded NUL) must not crash the read: treat it as
        # non-authoritative and fall through to name resolution (Finding 3).
        path_authoritative = False
        if path and "/" not in repo:
            try:
                if Path(path).expanduser().resolve().name == repo:
                    path_authoritative = True
            except (OSError, ValueError):
                path_authoritative = False

        owner = name = None
        index = None
        first_error: Optional[str] = None

        if path_authoritative:
            # The folder wins: identity is derived from the path itself.
            try:
                owner, name = folder_repo_identity(path)
            except (OSError, ValueError) as exc:
                path_authoritative = False
                first_error = sanitize_error(exc)

        if owner is None:
            try:
                owner, name = parse_repo(repo, storage_path)
            except RepoNotFoundError as exc:
                first_error = str(exc)

        if owner is not None:
            index = store.load_index(owner, name)
            if index is None and first_error is None:
                first_error = f"Repository not indexed: {owner}/{name}"

        # Stale iff we HAVE an index whose age strictly exceeds the policy.
        # age_threshold_exceeded -> None (unparseable/future) is treated as
        # stale (fail-closed, CLAUDE.md rule 4).
        stale = index is not None and age_threshold_exceeded(
            getattr(index, "indexed_at", None)
        ) is not False

        # Fresh, present index -> serve directly (unchanged happy path).
        if index is not None and not stale:
            return cls(owner=owner, name=name, store=store, index=index)

        # From here the index is missing or stale. On-demand indexing needs a
        # usable path:
        #   - path_authoritative: identity already derived from the path.
        #   - otherwise: the supplied folder MUST hash-match the resolved
        #     identity, or serving its content under this known name would be
        #     directory-swap index poisoning (security req 7). A malformed path
        #     is treated as a non-match, never a crash (Finding 3).
        can_reindex = False
        if path:
            if path_authoritative:
                can_reindex = True
            else:
                try:
                    can_reindex = folder_repo_identity(path) == (owner, name)
                except (OSError, ValueError):
                    can_reindex = False

        # No usable path -> preserve today's behavior:
        #   missing -> the existing "not indexed"/"not found" error
        #   stale   -> serve the stale index (availability-monotonic) + flag
        if not can_reindex:
            if index is not None:
                return cls(owner=owner, name=name, store=store, index=index, stale=True)
            return {"error": first_error}

        # Index on demand through the existing validated pipeline. Never raises.
        idx = _run_ondemand_index(path, storage_path)
        if not idx.get("success"):
            # Fail-safe: serve a stale index if we had one, else the sanitized
            # index error, else the original error.
            if index is not None:
                return cls(owner=owner, name=name, store=store, index=index, stale=True)
            return {"error": idx.get("error") or first_error}

        # Reload under the authoritative identity (owner/name is the path's
        # identity when path_authoritative, and the matched identity otherwise).
        fresh = store.load_index(owner, name)
        if not fresh:
            return {"error": first_error}
        return cls(
            owner=owner,
            name=name,
            store=store,
            index=fresh,
            freshly_indexed=True,
            index_warnings=list(idx.get("warnings") or []),
        )

    def meta_fields(self) -> dict:
        """Index-provenance fields to merge into a handler's result ``_meta``.

        Empty when the served index was already present and fresh, so the
        common happy path adds no keys and output stays byte-stable for
        already-indexed repos. Surfaces on-demand indexing provenance and any
        truncation/parse warnings so caps are never dropped silently
        (CLAUDE.md rule 8 -- no data-loss silences).
        """
        fields: dict = {}
        if self.freshly_indexed:
            fields["freshly_indexed"] = True
        if self.stale:
            fields["stale"] = True
        if self.index_warnings:
            fields["index_warnings"] = list(self.index_warnings)
        return fields

    def error_meta(self) -> dict:
        """A ``_meta`` envelope for a POST-resolution error return.

        After a successful (possibly on-demand) resolve, an error that follows
        -- symbol-not-found, "no symbol at line", graph-build failure -- must
        still carry ``freshly_indexed``/``stale``/``index_warnings`` so a fresh
        build (or truncation) is never silently dropped just because the
        requested symbol turned out to be absent (CLAUDE.md rule 8). Matches
        the QA-finding-4 pattern used by get_file_outline/get_file_tree.
        """
        meta = make_meta(source="code_index", trusted=False)
        meta.update(self.meta_fields())
        return meta


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
    *,
    path: Optional[str] = None,
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
        path: Optional host filesystem path of the repo working folder.
            Forwarded to :meth:`RepoContext.resolve` so a missing/stale
            index can be built on demand through the validated pipeline.

    Returns:
        On success a 6-tuple ``(owner, name, index, graph, symbol_info,
        ctx)`` where *symbol_info* is the symbol dict when *symbol_id* was
        provided, or ``None`` otherwise, and *ctx* is the resolved
        :class:`RepoContext` (carries ``freshly_indexed``/``stale``/
        ``index_warnings`` for the caller's ``_meta`` via
        :meth:`RepoContext.meta_fields`).

        On failure a plain ``dict`` with an ``"error"`` key that the
        caller should return directly.
    """
    ctx = RepoContext.resolve(repo, storage_path, path=path)
    if isinstance(ctx, dict):
        return ctx

    owner, name, index = ctx.owner, ctx.name, ctx.index

    # Verify target symbol exists (when requested)
    symbol_info = None
    if symbol_id is not None:
        symbol_info = index.get_symbol(symbol_id)
        if not symbol_info:
            # Post-resolution error: keep on-demand/staleness provenance.
            return {"error": f"Symbol not found: {symbol_id}", "_meta": ctx.error_meta()}

    # Build graph from index
    try:
        graph = CodeGraph.get_or_build(index.symbols)
    except (ValueError, TypeError, KeyError):
        return {"error": "Failed to build code graph", "_meta": ctx.error_meta()}

    return (owner, name, index, graph, symbol_info, ctx)
