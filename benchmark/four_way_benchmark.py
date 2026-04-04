#!/usr/bin/env python3
"""
Four-way code intelligence benchmark:
  codesight-mcp vs jCodeMunch vs CodeGraphContext vs No MCP (baseline)

Measures:
  1. Indexing time (seconds)
  2. Token efficiency per query (char/4 estimate)
  3. Query latency (ms)
  4. Result quality (symbols found, source included)

Usage:
  uv run python benchmark/four_way_benchmark.py [--target PATH] [--format table|json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path


# ---------------------------------------------------------------------------
# Token counting
# ---------------------------------------------------------------------------
def count_tokens(text: str) -> int:
    return len(text) // 4


# ---------------------------------------------------------------------------
# Spotlighting stripper (codesight-mcp)
# ---------------------------------------------------------------------------
_WRAPPER = re.compile(
    r"<<<UNTRUSTED_CODE_[0-9a-f]+>>>(.*?)<<<END_UNTRUSTED_CODE_[0-9a-f]+>>>",
    re.DOTALL,
)


def unwrap(s: str) -> str:
    m = _WRAPPER.search(s)
    return m.group(1).strip() if m else s


# ---------------------------------------------------------------------------
# Source file baseline
# ---------------------------------------------------------------------------
SOURCE_EXTENSIONS = {".py", ".rs", ".go", ".ts", ".js", ".java", ".cs"}
SKIP_DIRS = {"_storage", ".venv", "__pycache__", ".git", "node_modules", ".mypy_cache"}


def count_baseline_tokens(target: Path) -> tuple[int, int, int]:
    """Return (token_count, file_count, loc) for all source files."""
    tokens = files = loc = 0
    for root, dirs, filenames in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in filenames:
            if Path(fname).suffix in SOURCE_EXTENSIONS:
                fpath = Path(root) / fname
                try:
                    text = fpath.read_text(errors="replace")
                    tokens += count_tokens(text)
                    files += 1
                    loc += text.count("\n")
                except OSError:
                    pass
    return tokens, files, loc


# ---------------------------------------------------------------------------
# Queries — natural language questions an AI agent would ask
# ---------------------------------------------------------------------------
QUERIES = [
    "How does path validation work?",
    "How are secrets detected and redacted?",
    "How does the batch summarizer work?",
    "How are symbols indexed from source files?",
    "How is rate limiting implemented?",
    "How are symbols searched and scored?",
    "How does atomic index write work?",
    "How are file paths validated for traversal?",
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
@dataclass
class QueryResult:
    query: str
    tokens: int
    latency_ms: float
    symbols_found: int


@dataclass
class ToolResult:
    name: str
    index_time_s: float
    queries: list[QueryResult] = field(default_factory=list)

    @property
    def avg_tokens(self) -> int:
        return sum(q.tokens for q in self.queries) // max(len(self.queries), 1)

    @property
    def avg_latency_ms(self) -> float:
        return sum(q.latency_ms for q in self.queries) / max(len(self.queries), 1)


# ---------------------------------------------------------------------------
# Tool runners
# ---------------------------------------------------------------------------
def _supports_param(fn, param: str) -> bool:
    import inspect
    try:
        return param in inspect.signature(fn).parameters
    except (ValueError, TypeError):
        return False


def run_codesight(target: Path, queries: list[str], top_k: int) -> ToolResult:
    from codesight_mcp.tools.index_folder import index_folder
    from codesight_mcp.tools.search_symbols import search_symbols
    from codesight_mcp.tools.get_symbol import get_symbols

    with tempfile.TemporaryDirectory(prefix="cs_bench_") as tmp:
        kwargs = dict(path=str(target), use_ai_summaries=False, storage_path=tmp)
        if _supports_param(index_folder, "allowed_roots"):
            kwargs["allowed_roots"] = [str(target.resolve().parent)]

        t0 = time.time()
        idx = index_folder(**kwargs)
        index_time = time.time() - t0

        repo = idx["repo"]
        result = ToolResult(name="codesight-mcp", index_time_s=index_time)

        for query in queries:
            t0 = time.time()
            sr = search_symbols(repo=repo, query=query, max_results=5, storage_path=tmp)
            results = sr.get("results", [])
            raw_ids = [r.get("id", "") for r in results[:top_k]]
            ids = [unwrap(rid) for rid in raw_ids]
            gs = get_symbols(repo=repo, symbol_ids=ids, storage_path=tmp)
            latency = (time.time() - t0) * 1000

            response_text = json.dumps(gs)
            result.queries.append(QueryResult(
                query=query,
                tokens=count_tokens(response_text),
                latency_ms=latency,
                symbols_found=len(ids),
            ))

        return result


def run_jcodemunch(target: Path, queries: list[str], top_k: int) -> ToolResult:
    from jcodemunch_mcp.tools.index_folder import index_folder
    from jcodemunch_mcp.tools.search_symbols import search_symbols
    from jcodemunch_mcp.tools.get_symbol import get_symbols

    with tempfile.TemporaryDirectory(prefix="jcm_bench_") as tmp:
        t0 = time.time()
        idx = index_folder(path=str(target), use_ai_summaries=False, storage_path=tmp)
        index_time = time.time() - t0

        repo = idx.get("repo", "")
        result = ToolResult(name="jcodemunch", index_time_s=index_time)

        for query in queries:
            t0 = time.time()
            sr = search_symbols(repo=repo, query=query, max_results=5, storage_path=tmp)
            results = sr.get("results", [])
            ids = [r.get("id", "") for r in results[:top_k]]
            gs = get_symbols(repo=repo, symbol_ids=ids, storage_path=tmp)
            latency = (time.time() - t0) * 1000

            response_text = json.dumps(gs)
            result.queries.append(QueryResult(
                query=query,
                tokens=count_tokens(response_text),
                latency_ms=latency,
                symbols_found=len(ids),
            ))

        return result


def run_codegraphcontext(target: Path, queries: list[str], top_k: int) -> ToolResult:
    from codegraphcontext.core import get_database_manager
    from codegraphcontext.core.jobs import JobManager
    from codegraphcontext.tools.graph_builder import GraphBuilder
    from codegraphcontext.tools.code_finder import CodeFinder
    import asyncio

    db = get_database_manager()
    jm = JobManager()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    gb = GraphBuilder(db, jm, loop)

    t0 = time.time()
    loop.run_until_complete(gb.build_graph_from_path_async(target))
    index_time = time.time() - t0

    cf = CodeFinder(db)
    result = ToolResult(name="codegraphcontext", index_time_s=index_time)

    # CGC uses specific finders, not unified natural language search.
    # Use find_by_content (closest to full-text search) plus function/class name lookups.
    for query in queries:
        terms = _extract_search_terms(query)
        t0 = time.time()

        all_results = []

        # Primary: content search with key terms
        for term in terms[:3]:
            try:
                hits = cf.find_by_content(term)
                all_results.extend(hits)
            except Exception:
                pass

        # Secondary: function/class name search with fuzzy matching
        for term in terms[:2]:
            try:
                hits = cf.find_by_function_name(term, True)
                all_results.extend(hits)
            except Exception:
                pass
            try:
                hits = cf.find_by_class_name(term, True)
                all_results.extend(hits)
            except Exception:
                pass

        # Deduplicate by (name, path) to avoid counting same symbol twice
        seen = set()
        unique = []
        for r in all_results:
            key = (r.get("name", ""), r.get("path", ""))
            if key not in seen:
                seen.add(key)
                unique.append(r)

        truncated = unique[:top_k]
        latency = (time.time() - t0) * 1000

        response_text = json.dumps(truncated, default=str)
        result.queries.append(QueryResult(
            query=query,
            tokens=count_tokens(response_text),
            latency_ms=latency,
            symbols_found=len(truncated),
        ))

    # Clean up
    try:
        gb.delete_repository_from_graph(str(target))
    except Exception:
        pass

    return result


def run_no_mcp(target: Path, queries: list[str], top_k: int) -> ToolResult:
    """Baseline: read all source files (what an AI does without any MCP tool)."""
    t0 = time.time()
    all_text = []
    for root, dirs, filenames in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in filenames:
            if Path(fname).suffix in SOURCE_EXTENSIONS:
                fpath = Path(root) / fname
                try:
                    all_text.append(fpath.read_text(errors="replace"))
                except OSError:
                    pass
    index_time = time.time() - t0

    full_content = "\n".join(all_text)
    full_tokens = count_tokens(full_content)

    result = ToolResult(name="no-mcp", index_time_s=index_time)

    for query in queries:
        # Without MCP, the AI reads ALL files — same token cost for every query
        result.queries.append(QueryResult(
            query=query,
            tokens=full_tokens,
            latency_ms=0,
            symbols_found=0,
        ))

    return result


# ---------------------------------------------------------------------------
# Query term extraction (for CGC which needs specific search terms)
# ---------------------------------------------------------------------------
_STOP_WORDS = {"how", "does", "the", "is", "are", "a", "an", "and", "for", "from", "work", "what"}


def _extract_search_terms(query: str) -> list[str]:
    words = re.findall(r"[a-zA-Z_]+", query.lower())
    return [w for w in words if w not in _STOP_WORDS and len(w) > 2]


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------
def print_table(results: list[ToolResult], baseline_tokens: int, file_count: int, loc: int, target: Path) -> None:
    print()
    print("Four-Way Code Intelligence Benchmark")
    print("=" * 60)
    print(f"Target:    {target}  ({file_count} files, {loc:,} LOC)")
    print(f"Baseline:  ~{baseline_tokens:,} tokens (reading all source files)")
    print(f"Queries:   {len(QUERIES)}")
    print()

    # --- Indexing ---
    print("Indexing Performance")
    print("-" * 40)
    for r in results:
        print(f"  {r.name:<22} {r.index_time_s:>6.2f}s")
    print()

    # --- Token efficiency ---
    names = [r.name for r in results]
    col_w = max(max(len(n) for n in names) + 2, 14)
    q_width = max(len(q) for q in QUERIES) + 2

    print("Token Efficiency (tokens per query)")
    print("-" * (q_width + col_w * len(results) + len(results) * 2))

    header = f"{'Query':<{q_width}}" + "".join(f"{r.name:>{col_w}}" for r in results)
    print(header)
    print("-" * len(header))

    for i, q in enumerate(QUERIES):
        row = f"{q:<{q_width}}"
        for r in results:
            tok = r.queries[i].tokens
            row += f"{tok:>{col_w},}"
        print(row)

    print("-" * len(header))
    avg_row = f"{'Average':<{q_width}}"
    for r in results:
        avg_row += f"{r.avg_tokens:>{col_w},}"
    print(avg_row)
    print()

    # --- Reduction summary ---
    print("Reduction vs No-MCP Baseline")
    print("-" * 40)
    for r in results:
        if r.name == "no-mcp":
            continue
        pct = (1 - r.avg_tokens / baseline_tokens) * 100
        mult = baseline_tokens // max(r.avg_tokens, 1)
        print(f"  {r.name:<22} {pct:>5.1f}%  (~{mult}x fewer tokens)")
    print()

    # --- Query latency ---
    print("Query Latency (avg ms)")
    print("-" * 40)
    for r in results:
        if r.name == "no-mcp":
            continue
        print(f"  {r.name:<22} {r.avg_latency_ms:>6.1f}ms")
    print()

    # --- Spotlighting overhead ---
    cs = next((r for r in results if r.name == "codesight-mcp"), None)
    jcm = next((r for r in results if r.name == "jcodemunch"), None)
    if cs and jcm:
        overhead = cs.avg_tokens - jcm.avg_tokens
        pct = (overhead / jcm.avg_tokens) * 100 if jcm.avg_tokens else 0
        print("Spotlighting Overhead (codesight-mcp vs jcodemunch)")
        print("-" * 40)
        print(f"  +{overhead:,} tokens avg/query ({pct:.0f}% overhead)")
        print("  This is the cost of security boundary markers")
        print("  that prevent prompt injection attacks.")
        print()

    # --- Security features ---
    print("Feature Comparison")
    print("-" * 70)
    features = [
        ("Security: path validation", "Y", "N", "N", "-"),
        ("Security: spotlighting", "Y", "N", "N", "-"),
        ("Security: secret redaction", "Y", "N", "N", "-"),
        ("Security: rate limiting", "Y", "N", "N", "-"),
        ("Security: error sanitization", "Y", "N", "N", "-"),
        ("Code graph (callers/callees)", "Y", "N", "Y", "-"),
        ("Type hierarchy", "Y", "N", "Y", "-"),
        ("Dead code detection", "Y", "N", "Y", "-"),
        ("Impact analysis", "Y", "N", "N", "-"),
        ("AI summaries", "Y", "Y", "N", "-"),
        ("GitHub remote indexing", "Y", "Y", "N", "-"),
        ("External DB required", "N", "N", "Y", "-"),
    ]
    hdr = f"{'Feature':<35}{'codesight':>10}{'jcodemunch':>12}{'CGC':>8}{'no-mcp':>8}"
    print(hdr)
    print("-" * len(hdr))
    for feat, *vals in features:
        row = f"{feat:<35}"
        for v in vals:
            row += f"{v:>10}" if vals.index(v) == 1 else f"{v:>12}" if vals.index(v) == 1 else f"{v:>8}"
        # Fix alignment
        print(f"{feat:<35}{vals[0]:>10}{vals[1]:>12}{vals[2]:>8}{vals[3]:>8}")
    print()


def print_json(results: list[ToolResult], baseline_tokens: int, file_count: int, loc: int, target: Path) -> None:
    output = {
        "target": str(target),
        "file_count": file_count,
        "loc": loc,
        "baseline_tokens": baseline_tokens,
        "tokenizer": "char/4",
        "tools": [],
    }
    for r in results:
        tool_data = {
            "name": r.name,
            "index_time_s": round(r.index_time_s, 3),
            "avg_tokens": r.avg_tokens,
            "avg_latency_ms": round(r.avg_latency_ms, 1),
            "reduction_pct": round((1 - r.avg_tokens / baseline_tokens) * 100, 1) if r.name != "no-mcp" else 0,
            "queries": [asdict(q) for q in r.queries],
        }
        output["tools"].append(tool_data)
    print(json.dumps(output, indent=2))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="Four-way code intelligence benchmark")
    parser.add_argument("--target", default=str(Path(__file__).parent.parent / "src" / "codesight_mcp"))
    parser.add_argument("--top-k", type=int, default=3)
    parser.add_argument("--format", choices=["table", "json"], default="table")
    parser.add_argument("--tool", nargs="*", default=["codesight-mcp", "jcodemunch", "codegraphcontext", "no-mcp"],
                        help="Tools to benchmark (default: all four)")
    args = parser.parse_args()

    target = Path(args.target).resolve()
    if not target.exists():
        print(f"Error: {target} does not exist", file=sys.stderr)
        sys.exit(1)

    print("Measuring baseline...", file=sys.stderr)
    baseline_tokens, file_count, loc = count_baseline_tokens(target)

    results: list[ToolResult] = []
    runners = {
        "codesight-mcp": run_codesight,
        "jcodemunch": run_jcodemunch,
        "codegraphcontext": run_codegraphcontext,
        "no-mcp": run_no_mcp,
    }

    for tool_name in args.tool:
        if tool_name not in runners:
            print(f"Unknown tool: {tool_name}", file=sys.stderr)
            continue
        print(f"Benchmarking {tool_name}...", file=sys.stderr)
        try:
            result = runners[tool_name](target, QUERIES, args.top_k)
            results.append(result)
        except Exception as e:
            print(f"  {tool_name} failed: {e}", file=sys.stderr)

    if not results:
        print("No tools ran successfully.", file=sys.stderr)
        sys.exit(1)

    if args.format == "json":
        print_json(results, baseline_tokens, file_count, loc, target)
    else:
        print_table(results, baseline_tokens, file_count, loc, target)


if __name__ == "__main__":
    main()
