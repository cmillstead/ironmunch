"""Search symbols across a repository."""

from typing import Optional

from ..core.errors import sanitize_error
from ..core.limits import MAX_SEARCH_RESULTS
from ..core.boundaries import make_meta, wrap_untrusted_content
from ..embeddings.scoring import cosine_similarity, hybrid_rank
from ..embeddings.store import EmbeddingStore
from ..embeddings.providers import get_embedding_provider, get_embedding_provider_or_reason
from ..parser.extractor import SUPPORTED_LANGUAGES
from ..security import sanitize_signature_for_api
from ._common import RepoContext, timed, elapsed_ms, calculate_symbol_score
from mcp.types import ToolAnnotations
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
    semantic: bool = False,
    semantic_weight: float = 0.7,
    semantic_only: bool = False,
    provider=None,
) -> dict:
    """Search symbols in a single repo. Returns result dict."""
    ctx = RepoContext.resolve(repo, storage_path)
    if isinstance(ctx, dict):
        return ctx
    owner, name, index = ctx.owner, ctx.name, ctx.index

    # --- Keyword path ---
    results = []
    if not semantic_only:
        results = index.search(query, kind=kind, file_pattern=file_pattern)
        if language:
            results = [s for s in results if s.get("language") == language]

    # --- Semantic path ---
    # Skip semantic when weight is 0 AND not semantic_only — provider may not be available
    # semantic_only always runs semantic regardless of weight
    semantic_scores: dict[str, float] = {}
    if semantic_only or (semantic and semantic_weight != 0.0):
        try:
            if provider is None:
                provider = get_embedding_provider()
            if provider is None:
                return {
                    "error": "Semantic search requires codesight-mcp[semantic]. "
                    "Install with: pip install codesight-mcp[semantic]"
                }

            store = EmbeddingStore(owner, name, storage_path)
            store.load()  # explicit load to get model/dimensions from disk

            # Model mismatch: invalidate if different model or dimensions
            if store.model and store.model != provider.model_name:
                all_cached_ids = list(store._vectors.keys())
                store.invalidate(all_cached_ids)
            if store.dimensions and store.dimensions != provider.dimensions:
                all_cached_ids = list(store._vectors.keys())
                store.invalidate(all_cached_ids)

            store.model = provider.model_name
            store.dimensions = provider.dimensions

            # Filter symbols (same filters as keyword path)
            all_symbols = index.symbols
            if kind:
                all_symbols = [s for s in all_symbols if s.get("kind") == kind]
            if file_pattern:
                all_symbols = [s for s in all_symbols if index._match_pattern(s.get("file", ""), file_pattern)]
            if language:
                all_symbols = [s for s in all_symbols if s.get("language") == language]

            # Lazy embed missing
            symbol_ids = [s["id"] for s in all_symbols]
            missing = store.missing(symbol_ids)
            if missing:
                texts = []
                for sid in missing:
                    sym = index.get_symbol(sid)
                    if sym:
                        # Rich embedding text: qualified name, kind, summary, docstring, signature, file
                        parts = [
                            sym.get("qualified_name", sym.get("name", "")),
                            sym.get("kind", ""),
                            sym.get("summary", ""),
                            sym.get("docstring", ""),
                            sym.get("signature", ""),
                            sym.get("file", ""),
                        ]
                        text = " | ".join(p for p in parts if p)
                    else:
                        text = ""
                    texts.append(text)
                new_vecs = provider.embed(texts)
                for sid, vec in zip(missing, new_vecs):
                    store.set(sid, vec)
                store.save()

            query_vec = provider.embed([query])[0]

            for sym in all_symbols:
                vec = store.get(sym["id"])
                if vec:
                    semantic_scores[sym["id"]] = cosine_similarity(query_vec, vec)
        except Exception as exc:
            return {"error": sanitize_error(exc)}

    # --- Merge and rank ---
    scored_results = []
    query_lower = query.lower()
    query_words = set(query_lower.split())

    # Determine effective mode for ranking
    # semantic_only always runs semantic regardless of weight
    effective_semantic_only = semantic_only
    effective_semantic = (semantic and semantic_weight != 0.0) and not semantic_only

    if effective_semantic_only:
        # Pure semantic
        for sym in all_symbols:
            sim = semantic_scores.get(sym["id"], 0.0)
            if sim > 0.1:
                scored_results.append({
                    "id": wrap_untrusted_content(sym["id"]),
                    "kind": sym["kind"],
                    "name": wrap_untrusted_content(sym["name"]),
                    "file": wrap_untrusted_content(sym["file"]),
                    "line": sym["line"],
                    "signature": wrap_untrusted_content(sym["signature"]),
                    "summary": wrap_untrusted_content(sym.get("summary", "")),
                    "score": sim,
                    "repo": f"{owner}/{name}",
                })

    elif effective_semantic:
        # Hybrid — weight-aware inclusion
        for sym in all_symbols:
            kw_score = calculate_symbol_score(sym, query_lower, query_words)
            sim = semantic_scores.get(sym["id"], 0.0)

            # Weight-aware inclusion rule
            # Note: semantic_weight==0.0 is handled by effective_semantic (falls to keyword path)
            if semantic_weight == 1.0:
                if sim < 0.1:
                    continue
            else:
                if kw_score <= 0 and sim < 0.1:
                    continue

            final_score = hybrid_rank(kw_score, sim, semantic_weight)
            scored_results.append({
                "id": wrap_untrusted_content(sym["id"]),
                "kind": sym["kind"],
                "name": wrap_untrusted_content(sym["name"]),
                "file": wrap_untrusted_content(sym["file"]),
                "line": sym["line"],
                "signature": wrap_untrusted_content(sym["signature"]),
                "summary": wrap_untrusted_content(sym.get("summary", "")),
                "score": final_score,
                "repo": f"{owner}/{name}",
            })

    else:
        # Pure keyword (existing behavior, UNCHANGED)
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

    scored_results.sort(key=lambda x: x["score"], reverse=True)
    # Round scores for display after sorting (preserves ranking precision)
    for r in scored_results:
        r["score"] = round(r["score"], 2)
    # Use full untruncated count for keyword path, scored_results for semantic
    all_count = len(results) if not (effective_semantic or effective_semantic_only) else len(scored_results)
    response = {
        "repo": f"{owner}/{name}",
        "results": scored_results[:max_results],
        "total_symbols": len(index.symbols),
        "all_results_count": all_count,
    }
    # Only add search_mode when semantic actually ran (not when weight=0 fell to keyword)
    if effective_semantic_only:
        response["search_mode"] = "semantic_only"
    elif effective_semantic:
        response["search_mode"] = "hybrid"
    return response


def search_symbols(
    repo: Optional[str] = None,
    query: str = "",
    kind: Optional[str] = None,
    file_pattern: Optional[str] = None,
    language: Optional[str] = None,
    max_results: int = 10,
    repos: Optional[list[str]] = None,
    storage_path: Optional[str] = None,
    semantic: bool = False,
    semantic_weight: float = 0.7,
    semantic_only: bool = False,
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
        semantic: Enable semantic (embedding-based) search.
        semantic_weight: Weight for semantic vs keyword scoring (0.0-1.0).
        semantic_only: Use only semantic scoring, skip keyword matching.

    Returns:
        Dict with search results and _meta envelope.
    """
    if not isinstance(query, str) or not query.strip():
        return {"error": "query must be a non-empty string"}

    # semantic_only implies semantic
    if semantic_only:
        semantic = True

    # Validate semantic_weight
    if not (0.0 <= semantic_weight <= 1.0):
        return {"error": "semantic_weight must be between 0.0 and 1.0"}

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

    # Construct provider ONCE before repo loop when semantic enabled
    # semantic_only always needs provider; semantic skips when weight==0.0
    provider = None
    if semantic_only or (semantic and semantic_weight != 0.0):
        try:
            provider, reason = get_embedding_provider_or_reason()
        except Exception as exc:
            return {"error": sanitize_error(exc)}
        if provider is None:
            if reason.startswith("not_implemented:"):
                prov_name = reason.split(":", 1)[1]
                return {
                    "error": f"Embedding provider '{prov_name}' is not yet implemented. "
                    "Use 'local' or omit CODESIGHT_EMBED_PROVIDER."
                }
            elif reason == "disabled":
                return {"error": "Semantic search is disabled via CODESIGHT_NO_SEMANTIC=1"}
            else:
                return {
                    "error": "Semantic search requires codesight-mcp[semantic]. "
                    "Install with: pip install codesight-mcp[semantic]"
                }

    # Search across all repos
    all_scored = []
    total_symbols = 0
    truncated = False
    errors = []
    repos_searched = []

    for r in repo_list:
        result = _search_single_repo(
            r, query, kind, file_pattern, language, max_results, storage_path,
            semantic=semantic, semantic_weight=semantic_weight, semantic_only=semantic_only, provider=provider,
        )
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

    if semantic or semantic_only:
        response["search_mode"] = "semantic_only" if semantic_only else "hybrid"

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
            "semantic": {
                "type": "boolean",
                "description": "Enable semantic (embedding-based) search. Requires codesight-mcp[semantic]. Default: false.",
                "default": False,
            },
            "semantic_weight": {
                "type": "number",
                "description": (
                    "Weight for semantic vs keyword scoring "
                    "(0.0 = keyword only, 1.0 = semantic only). Default: 0.7."
                ),
                "default": 0.7,
                "minimum": 0.0,
                "maximum": 1.0,
            },
            "semantic_only": {
                "type": "boolean",
                "description": "Use only semantic scoring, skip keyword matching entirely. Default: false.",
                "default": False,
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
        semantic=args.get("semantic", False),
        semantic_weight=args.get("semantic_weight", 0.7),
        semantic_only=args.get("semantic_only", False),
    ),
    untrusted=True,
    required_args=["query"],
    annotations=ToolAnnotations(title="Search Symbols", readOnlyHint=True, openWorldHint=False),
))
