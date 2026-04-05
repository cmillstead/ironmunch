"""In-memory code graph for relationship queries."""

import hashlib
import threading
from collections import defaultdict, deque
from typing import Optional


# Extensions whose languages use dotted module imports (e.g., import pkg.utils).
# Other languages (C/C++, etc.) use path-based includes and should NOT get
# dotted keys to avoid cross-language collisions (e.g., pkg/utils.h -> pkg.utils
# would incorrectly match a Python import of an external "pkg.utils" package).
_DOTTED_IMPORT_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".java", ".kt", ".kts", ".scala", ".groovy",
    ".clj", ".cljs", ".cljc",  # Clojure
    ".ex", ".exs",  # Elixir
    ".erl", ".hrl",  # Erlang
    ".jl",  # Julia
})


def _build_import_resolution_map(source_files: list[str]) -> dict[str, str | None]:
    """Build a multi-key lookup mapping import strings to source file paths.

    For each source file, generates up to four match keys:
    - Original path: the full file path (Foo.h -> Foo.h, for C-family #include)
    - Full path stem: strip extension (pkg/utils.py -> pkg/utils)
    - Dotted form: replace / with . in stem (pkg/utils -> pkg.utils)
      — only for languages that use dotted module imports
    - Basename: filename without extension (utils)

    Keys that map to multiple files are marked as ambiguous (None).
    Returns dict mapping key -> file_path (unambiguous) or key -> None (ambiguous).
    """
    key_to_files: dict[str, list[str]] = defaultdict(list)

    for f in source_files:
        stem = f.rsplit(".", 1)[0] if "." in f else f
        ext = f[f.rfind("."):] if "." in f else ""
        basename = stem.rsplit("/", 1)[-1] if "/" in stem else stem

        # Include the original path so C-family #include "Foo.h" resolves
        keys = [f, stem, basename]
        # Only add dotted form for languages that use dotted module imports
        if ext in _DOTTED_IMPORT_EXTENSIONS:
            keys.append(stem.replace("/", "."))
        for key in keys:
            key_to_files[key].append(f)

    # Resolve: single file = unambiguous, multiple = ambiguous (None)
    result: dict[str, str | None] = {}
    for key, files in key_to_files.items():
        unique = list(set(files))
        result[key] = unique[0] if len(unique) == 1 else None

    return result


# Hard ceiling for all traversals.
_MAX_DEPTH_LIMIT: int = 50


def _symbol_fingerprint(symbols: list[dict]) -> str:
    """Compute a collision-resistant fingerprint from symbol data for cache keying.

    ADV-LOW-4: Uses SHA-256 instead of Python's hash() to avoid collisions
    that could return stale cached graphs.

    Includes symbol IDs, call lists, inherits_from, imports, and implements
    so that changes to function bodies (adding/removing calls) invalidate
    the cached graph.
    """
    parts = []
    for sym in sorted(symbols, key=lambda s: s.get("id", "")):
        sid = sym.get("id", "")
        calls = ",".join(sorted(sym.get("calls", [])))
        inherits = ",".join(sorted(sym.get("inherits_from", [])))
        imports = ",".join(sorted(sym.get("imports", [])))
        implements = ",".join(sorted(sym.get("implements", [])))
        parts.append(f"{sid}|{calls}|{inherits}|{imports}|{implements}")
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()


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
    _graph_cache_lock: threading.Lock = threading.Lock()
    _CACHE_MAX_SIZE: int = 8
    _CACHE_MAX_BYTES: int = 50_000_000  # 50 MB budget for cached graphs

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
        with cls._graph_cache_lock:
            graph = cls._graph_cache.get(fingerprint)
            if graph is not None:
                return graph

        # Build outside the lock to avoid holding it during expensive work
        graph = cls.build(symbols)
        new_size = graph._approx_size()

        with cls._graph_cache_lock:
            # Check again in case another thread built it while we were building
            if fingerprint in cls._graph_cache:
                return cls._graph_cache[fingerprint]

            # Evict oldest entries if count limit or memory budget exceeded
            total = sum(g._approx_size() for g in cls._graph_cache.values())
            while cls._graph_cache and (
                len(cls._graph_cache) >= cls._CACHE_MAX_SIZE
                or total + new_size > cls._CACHE_MAX_BYTES
            ):
                oldest_key = next(iter(cls._graph_cache))
                total -= cls._graph_cache[oldest_key]._approx_size()
                del cls._graph_cache[oldest_key]

            cls._graph_cache[fingerprint] = graph
        return graph

    @classmethod
    def clear_cache(cls) -> None:
        """Clear the graph cache. Called after re-indexing or cache invalidation."""
        with cls._graph_cache_lock:
            cls._graph_cache.clear()

    def _approx_size(self) -> int:
        """Estimate memory usage of this graph in bytes."""
        count = 0
        for d in (self._calls_fwd, self._calls_rev, self._imports_fwd, self._imports_rev,
                  self._inherits_fwd, self._inherits_rev, self._implements_fwd, self._implements_rev):
            for k, v in d.items():
                count += len(k) + sum(len(s) for s in v)
        count += sum(len(k) for k in self._symbols_by_id)
        return count * 2  # rough estimate: 2 bytes per char

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

    def get_symbol(self, symbol_id: str) -> dict | None:
        """Look up a symbol dict by ID, or return None if not found."""
        return self._symbols_by_id.get(symbol_id)

    def all_symbols(self) -> dict[str, dict]:
        """Return a copy of the symbol-by-id mapping."""
        return dict(self._symbols_by_id)

    def get_callers(self, symbol_id: str) -> list[str]:
        """Return symbol IDs that call *symbol_id* (reverse call graph)."""
        return sorted(self._calls_rev.get(symbol_id, set()))

    def get_callees(self, symbol_id: str) -> list[str]:
        """Return symbol IDs that *symbol_id* calls (forward call graph)."""
        return sorted(self._calls_fwd.get(symbol_id, set()))

    # ADV-LOW-3: maximum paths returned by get_call_chain to prevent
    # exponential BFS expansion in highly connected graphs.
    _MAX_CALL_CHAIN_PATHS: int = 5
    _MAX_BFS_QUEUE_SIZE: int = 10_000

    def get_call_chain(
        self,
        from_id: str,
        to_id: str,
        max_depth: int = 10,
    ) -> dict:
        """Find call paths from *from_id* to *to_id* via BFS.

        Args:
            from_id: Starting symbol ID.
            to_id: Target symbol ID.
            max_depth: Maximum path length (clamped to 50).

        Returns:
            Dict with ``paths`` (list of paths, each a list of symbol IDs)
            and ``truncated`` (bool, True if BFS queue was capped).
        """
        max_depth = _clamp_depth(max_depth)
        if from_id not in self._symbols_by_id or to_id not in self._symbols_by_id:
            return {"paths": [], "truncated": False}

        if from_id == to_id:
            return {"paths": [[from_id]], "truncated": False}

        paths: list[list[str]] = []
        queue: deque[list[str]] = deque([[from_id]])
        truncated = False

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
                    if len(queue) < self._MAX_BFS_QUEUE_SIZE:
                        queue.append(new_path)
                    else:
                        truncated = True
        return {"paths": paths, "truncated": truncated}

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

    # ------------------------------------------------------------------
    # PageRank
    # ------------------------------------------------------------------

    def pagerank(
        self,
        damping: float = 0.85,
        max_iterations: int = 50,
        tolerance: float = 0.0001,
    ) -> dict[str, float]:
        """Compute PageRank scores for all symbols in the call graph.

        Args:
            damping: Damping factor (probability of following a link). Default 0.85.
            max_iterations: Maximum iterations before stopping. Default 50.
            tolerance: Convergence threshold (max rank change). Default 0.0001.

        Returns:
            Dict mapping symbol_id -> rank score. Ranks sum to N (node count).
        """
        damping = max(0.1, min(damping, 0.99))
        max_iterations = max(1, min(max_iterations, 1000))
        tolerance = max(1e-10, min(tolerance, 1.0))

        nodes = list(self._symbols_by_id.keys())
        n = len(nodes)
        if n == 0:
            return {}

        # Initialize ranks equally
        rank = {nid: 1.0 for nid in nodes}

        for _ in range(max_iterations):
            # Collect rank from dangling nodes (no outgoing edges)
            dangling_sum = sum(
                rank[nid] for nid in nodes
                if not self._calls_fwd.get(nid, set())
            )

            new_rank: dict[str, float] = {}
            for nid in nodes:
                incoming = self._calls_rev.get(nid, set())
                # Base: teleportation + redistributed dangling rank
                total = (1.0 - damping) + damping * dangling_sum / n
                for caller in incoming:
                    out_degree = len(self._calls_fwd.get(caller, set()))
                    if out_degree > 0:
                        total += damping * rank[caller] / out_degree
                new_rank[nid] = total

            # Check convergence
            max_delta = max(abs(new_rank[nid] - rank[nid]) for nid in nodes)
            rank = new_rank
            if max_delta < tolerance:
                break

        return rank

    # ------------------------------------------------------------------
    # Circular dependency detection
    # ------------------------------------------------------------------

    def find_import_cycles(
        self,
        source_files: list[str],
        max_cycles: int = 20,
    ) -> tuple[list[list[str]], int, bool]:
        """Find circular dependencies using Tarjan SCC on normalized import edges.

        Builds a file-to-file adjacency graph from import edges, then runs
        iterative Tarjan's algorithm to find strongly connected components.
        SCCs with more than one node represent circular dependencies.

        Args:
            source_files: List of source file paths in the repo.
            max_cycles: Maximum number of cycles to return.

        Returns:
            Tuple of (cycles, total_count, truncated) where cycles is a list
            of sorted file lists, total_count is the total SCCs found, and
            truncated is True if total_count exceeded max_cycles.
        """
        resolution_map = _build_import_resolution_map(source_files)
        source_set = set(source_files)

        # Build file-to-file internal import adjacency
        adj: dict[str, set[str]] = defaultdict(set)
        for src_file in sorted(source_set):
            for imp in self._imports_fwd.get(src_file, set()):
                target = resolution_map.get(imp)
                if target is not None and target in source_set and target != src_file:
                    adj[src_file].add(target)

        # Ensure all source files with imports are nodes
        all_nodes = sorted(
            set(adj.keys()) | {t for targets in adj.values() for t in targets}
        )

        # Iterative Tarjan SCC
        index_counter = [0]
        stack: list[str] = []
        on_stack: set[str] = set()
        indices: dict[str, int] = {}
        lowlinks: dict[str, int] = {}
        sccs: list[list[str]] = []

        for node in all_nodes:
            if node in indices:
                continue
            # Iterative DFS
            work_stack: list[tuple[str, int]] = [(node, 0)]
            indices[node] = lowlinks[node] = index_counter[0]
            index_counter[0] += 1
            stack.append(node)
            on_stack.add(node)

            while work_stack:
                v, ni = work_stack[-1]
                neighbors = sorted(adj.get(v, set()))

                if ni < len(neighbors):
                    work_stack[-1] = (v, ni + 1)
                    w = neighbors[ni]
                    if w not in indices:
                        indices[w] = lowlinks[w] = index_counter[0]
                        index_counter[0] += 1
                        stack.append(w)
                        on_stack.add(w)
                        work_stack.append((w, 0))
                    elif w in on_stack:
                        lowlinks[v] = min(lowlinks[v], indices[w])
                else:
                    # Done with v
                    work_stack.pop()
                    if work_stack:
                        parent = work_stack[-1][0]
                        lowlinks[parent] = min(lowlinks[parent], lowlinks[v])

                    if lowlinks[v] == indices[v]:
                        scc: list[str] = []
                        while True:
                            w = stack.pop()
                            on_stack.discard(w)
                            scc.append(w)
                            if w == v:
                                break
                        if len(scc) > 1:
                            sccs.append(sorted(scc))

        # Sort SCCs by first element for deterministic output
        sccs.sort(key=lambda s: s[0])
        total = len(sccs)
        truncated = total > max_cycles
        return sccs[:max_cycles], total, truncated
