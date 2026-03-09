"""In-memory code graph for relationship queries."""

import hashlib
from collections import defaultdict, deque
from typing import Optional


# Hard ceiling for all traversals.
_MAX_DEPTH_LIMIT: int = 50


def _symbol_fingerprint(symbols: list[dict]) -> str:
    """Compute a collision-resistant fingerprint from symbol IDs for cache keying.

    ADV-LOW-4: Uses SHA-256 instead of Python's hash() to avoid collisions
    that could return stale cached graphs.
    """
    ids = sorted(sym.get("id", "") for sym in symbols)
    return hashlib.sha256("\n".join(ids).encode()).hexdigest()


def _clamp_depth(depth: int) -> int:
    """Clamp a user-supplied depth to the safe range [1, _MAX_DEPTH_LIMIT]."""
    return max(1, min(depth, _MAX_DEPTH_LIMIT))


class CodeGraph:
    """Lightweight in-memory code graph built from symbol dicts.

    Uses dict-of-sets adjacency lists with separate edge collections
    for calls, imports, inheritance, and interface implementation.
    All edges are stored in both forward and reverse directions.
    """

    def __init__(self) -> None:
        # Forward edges: source -> {targets}
        self._calls_fwd: dict[str, set[str]] = defaultdict(set)
        self._calls_rev: dict[str, set[str]] = defaultdict(set)

        self._imports_fwd: dict[str, set[str]] = defaultdict(set)  # file -> {modules}
        self._imports_rev: dict[str, set[str]] = defaultdict(set)  # module -> {files}

        self._inherits_fwd: dict[str, set[str]] = defaultdict(set)  # child -> {parents}
        self._inherits_rev: dict[str, set[str]] = defaultdict(set)  # parent -> {children}

        self._implements_fwd: dict[str, set[str]] = defaultdict(set)  # class -> {interfaces}
        self._implements_rev: dict[str, set[str]] = defaultdict(set)  # interface -> {classes}

        # Lookup tables populated during build.
        self._symbols_by_id: dict[str, dict] = {}
        self._name_to_ids: dict[str, list[str]] = defaultdict(list)

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def build(cls, symbols: list[dict]) -> "CodeGraph":
        """Build a CodeGraph from a list of serialised Symbol dicts.

        The dicts are expected to have the same shape as CodeIndex.symbols:
        keys ``id``, ``file``, ``name``, ``calls``, ``imports``,
        ``inherits_from``, and ``implements``.

        Args:
            symbols: Flat list of symbol dicts.

        Returns:
            A fully populated CodeGraph.
        """
        graph = cls()
        graph._index_symbols(symbols)
        graph._resolve_calls(symbols)
        graph._resolve_imports(symbols)
        graph._resolve_inheritance(symbols)
        return graph

    # Class-level graph cache: fingerprint -> CodeGraph
    _graph_cache: dict[str, "CodeGraph"] = {}
    _CACHE_MAX_SIZE: int = 8

    @classmethod
    def get_or_build(cls, symbols: list[dict]) -> "CodeGraph":
        """Return a cached CodeGraph, rebuilding only when symbols change.

        Caches up to 8 graphs keyed by a hash of the symbol ID set.
        When the index changes (symbols added/removed/changed IDs),
        the fingerprint changes and a fresh graph is built.

        Args:
            symbols: Flat list of symbol dicts.

        Returns:
            A cached or freshly built CodeGraph.
        """
        fingerprint = _symbol_fingerprint(symbols)
        graph = cls._graph_cache.get(fingerprint)
        if graph is not None:
            return graph

        # Evict oldest entries if cache is full
        while len(cls._graph_cache) >= cls._CACHE_MAX_SIZE:
            oldest_key = next(iter(cls._graph_cache))
            del cls._graph_cache[oldest_key]

        graph = cls.build(symbols)
        cls._graph_cache[fingerprint] = graph
        return graph

    @classmethod
    def clear_cache(cls) -> None:
        """Clear the graph cache. Called after re-indexing or cache invalidation."""
        cls._graph_cache.clear()

    def _index_symbols(self, symbols: list[dict]) -> None:
        """Build lookup tables from raw symbol dicts."""
        for sym in symbols:
            sid = sym.get("id", "")
            if not sid:
                continue
            self._symbols_by_id[sid] = sym
            name = sym.get("name", "")
            if name:
                self._name_to_ids[name].append(sid)

    def _resolve_name(self, name: str, context_file: str) -> Optional[str]:
        """Resolve an unqualified call name to a symbol ID.

        Heuristic priority:
        1. Same-file match (prefer the symbol defined in *context_file*).
        2. Unique name match (only one symbol has this name).
        3. Unresolved -- return ``None``.
        """
        candidates = self._name_to_ids.get(name, [])
        if not candidates:
            return None

        # 1. Same-file match.
        same_file = [c for c in candidates if self._symbols_by_id[c].get("file") == context_file]
        if len(same_file) == 1:
            return same_file[0]

        # 2. Unique global match.
        if len(candidates) == 1:
            return candidates[0]

        return None

    def _resolve_calls(self, symbols: list[dict]) -> None:
        """Populate call edges by resolving unqualified names."""
        for sym in symbols:
            sid = sym.get("id", "")
            ctx_file = sym.get("file", "")
            for call_name in sym.get("calls", []):
                target = self._resolve_name(call_name, ctx_file)
                if target and target != sid:
                    self._calls_fwd[sid].add(target)
                    self._calls_rev[target].add(sid)

    def _resolve_imports(self, symbols: list[dict]) -> None:
        """Populate import edges (file-level)."""
        for sym in symbols:
            file_path = sym.get("file", "")
            for imp in sym.get("imports", []):
                self._imports_fwd[file_path].add(imp)
                self._imports_rev[imp].add(file_path)

    def _resolve_inheritance(self, symbols: list[dict]) -> None:
        """Populate inheritance and implementation edges."""
        for sym in symbols:
            sid = sym.get("id", "")
            ctx_file = sym.get("file", "")

            for base in sym.get("inherits_from", []):
                target = self._resolve_name(base, ctx_file)
                target_key = target or base
                self._inherits_fwd[sid].add(target_key)
                self._inherits_rev[target_key].add(sid)

            for iface in sym.get("implements", []):
                target = self._resolve_name(iface, ctx_file)
                target_key = target or iface
                self._implements_fwd[sid].add(target_key)
                self._implements_rev[target_key].add(sid)

    # ------------------------------------------------------------------
    # Call-graph queries
    # ------------------------------------------------------------------

    def get_callers(self, symbol_id: str) -> list[str]:
        """Return symbol IDs that call *symbol_id* (reverse call graph)."""
        return sorted(self._calls_rev.get(symbol_id, set()))

    def get_callees(self, symbol_id: str) -> list[str]:
        """Return symbol IDs that *symbol_id* calls (forward call graph)."""
        return sorted(self._calls_fwd.get(symbol_id, set()))

    # ADV-LOW-3: maximum paths returned by get_call_chain to prevent
    # exponential BFS expansion in highly connected graphs.
    _MAX_CALL_CHAIN_PATHS: int = 5

    def get_call_chain(
        self,
        from_id: str,
        to_id: str,
        max_depth: int = 10,
    ) -> list[list[str]]:
        """Find call paths from *from_id* to *to_id* via BFS.

        Args:
            from_id: Starting symbol ID.
            to_id: Target symbol ID.
            max_depth: Maximum path length (clamped to 50).

        Returns:
            List of paths (up to _MAX_CALL_CHAIN_PATHS), where each path
            is a list of symbol IDs.
        """
        max_depth = _clamp_depth(max_depth)
        if from_id not in self._symbols_by_id or to_id not in self._symbols_by_id:
            return []

        paths: list[list[str]] = []
        queue: deque[list[str]] = deque([[from_id]])

        while queue:
            # ADV-LOW-3: early termination once enough paths are found
            if len(paths) >= self._MAX_CALL_CHAIN_PATHS:
                break
            path = queue.popleft()
            if len(path) - 1 >= max_depth:
                continue
            current = path[-1]
            for neighbour in self._calls_fwd.get(current, set()):
                if neighbour in path:
                    continue  # cycle
                new_path = path + [neighbour]
                if neighbour == to_id:
                    paths.append(new_path)
                    if len(paths) >= self._MAX_CALL_CHAIN_PATHS:
                        break
                else:
                    queue.append(new_path)
        return paths

    # ------------------------------------------------------------------
    # Type-hierarchy queries
    # ------------------------------------------------------------------

    def get_type_hierarchy(self, symbol_id: str) -> dict:
        """Return the inheritance tree around *symbol_id*.

        Returns a dict with ``parents`` (ancestors) and ``children``
        (descendants), each as a list of symbol ID / name strings.
        """
        return {
            "parents": sorted(self._inherits_fwd.get(symbol_id, set())),
            "children": sorted(self._inherits_rev.get(symbol_id, set())),
            "implements": sorted(self._implements_fwd.get(symbol_id, set())),
            "implemented_by": sorted(self._implements_rev.get(symbol_id, set())),
        }

    # ------------------------------------------------------------------
    # Import queries
    # ------------------------------------------------------------------

    def get_importers(self, file_path: str) -> list[str]:
        """Return file paths that import *file_path* (or a module matching it)."""
        return sorted(self._imports_rev.get(file_path, set()))

    def get_imports_of(self, file_path: str) -> list[str]:
        """Return modules/files imported by *file_path*."""
        return sorted(self._imports_fwd.get(file_path, set()))

    # ------------------------------------------------------------------
    # Impact analysis
    # ------------------------------------------------------------------

    def get_impact(self, symbol_id: str, max_depth: int = 5) -> set[str]:
        """Compute the transitive reverse closure of *symbol_id*.

        Walks reverse call edges to find everything that would be
        affected if *symbol_id* changed.

        Args:
            symbol_id: The symbol whose impact to compute.
            max_depth: Maximum traversal depth (clamped to 50).

        Returns:
            Set of affected symbol IDs (excludes *symbol_id* itself).
        """
        max_depth = _clamp_depth(max_depth)
        affected: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(symbol_id, 0)])

        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for caller in self._calls_rev.get(current, set()):
                if caller not in affected and caller != symbol_id:
                    affected.add(caller)
                    queue.append((caller, depth + 1))

        return affected
