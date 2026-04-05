#!/usr/bin/env python3
"""Competitive benchmark: measure codesight-mcp query latency on Flask 3.x.

Reproduces the 6 queries from the 2026-04-04 competitive benchmark report
against the Flask 3.1.0 corpus, measuring both cold-cache (fresh subprocess)
and warm-cache (primed in-process) latency.

Usage:
    .venv/bin/python scripts/benchmark_latency.py

Output:
    - Markdown table to stdout
    - JSON results to /tmp/benchmark-results.json
"""

import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

FLASK_TAG = "3.1.0"
FLASK_REPO_URL = "https://github.com/pallets/flask.git"
WARM_RUNS = 5  # per query

def make_queries(repo_id: str) -> list[dict]:
    """Build query list with the actual repo identifier."""
    return [
        {
            "name": "Symbol search (\"Flask\")",
            "func": "search_symbols",
            "kwargs": {"repo": repo_id, "query": "Flask"},
        },
        {
            "name": "Text search (\"route\")",
            "func": "search_text",
            "kwargs": {"repo": repo_id, "query": "route"},
        },
        {
            "name": "File outline (app.py)",
            "func": "get_file_outline",
            "kwargs": {"repo": repo_id, "file_path": "src/flask/app.py"},
        },
        {
            "name": "Repo outline",
            "func": "get_repo_outline",
            "kwargs": {"repo": repo_id},
        },
        {
            "name": "Symbol lookup (\"add_url_rule\")",
            "func": "get_symbol",
            # symbol_id resolved at runtime after indexing
            "kwargs": {"repo": repo_id, "symbol_id": None},
        },
        {
            "name": "Complexity analysis",
            "func": "analyze_complexity",
            "kwargs": {"repo": repo_id},
        },
    ]

# Original baseline from 2026-04-04 benchmark (ms)
BASELINE = {
    "Symbol search (\"Flask\")": 163.8,
    "Text search (\"route\")": 146.2,
    "File outline (app.py)": 133.5,
    "Repo outline": 132.3,
    "Symbol lookup (\"add_url_rule\")": 156.1,
    "Complexity analysis": 142.3,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_codesight_commit() -> str:
    """Get the current codesight-mcp git commit SHA."""
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        capture_output=True, text=True, cwd=Path(__file__).resolve().parent.parent,
    )
    return result.stdout.strip()[:12]


def clone_flask(dest: Path) -> str:
    """Clone Flask at the pinned tag. Returns the commit SHA."""
    if dest.exists():
        shutil.rmtree(dest)
    subprocess.run(
        ["git", "clone", "--depth", "1", "--branch", FLASK_TAG, FLASK_REPO_URL, str(dest)],
        check=True, capture_output=True,
    )
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        capture_output=True, text=True, cwd=dest,
    )
    return result.stdout.strip()


def count_python_files(flask_dir: Path) -> tuple[int, int]:
    """Count .py files and lines in the Flask source."""
    py_files = list(flask_dir.rglob("*.py"))
    total_lines = 0
    for f in py_files:
        try:
            total_lines += len(f.read_text(errors="ignore").splitlines())
        except OSError:
            pass
    return len(py_files), total_lines


def resolve_add_url_rule_id(storage_path: str, repo_id: str) -> str:
    """Find the symbol ID for Flask.add_url_rule after indexing."""
    from codesight_mcp.tools.search_symbols import search_symbols
    result = search_symbols(
        repo=repo_id, query="add_url_rule", storage_path=storage_path,
    )
    if "error" in result:
        print(f"  Search error: {result['error']}")
    symbols = result.get("results", result.get("symbols", []))
    if not symbols:
        # Try broader search
        result2 = search_symbols(
            repo=repo_id, query="url_rule", storage_path=storage_path,
        )
        symbols = result2.get("symbols", [])
    for sym in symbols:
        if "add_url_rule" in sym.get("name", ""):
            return sym["id"]
    # Fallback: use any method from Flask app
    for sym in symbols:
        if sym.get("kind") in ("method", "function"):
            print(f"  Fallback symbol: {sym.get('name')} ({sym.get('id')})")
            return sym["id"]
    # Last resort: pick any symbol
    if symbols:
        return symbols[0]["id"]
    raise RuntimeError("Could not find add_url_rule symbol after indexing")


def run_query(func_name: str, kwargs: dict, storage_path: str) -> tuple[dict, float]:
    """Run a single query, return (result, elapsed_ms)."""
    # Import the tool handler
    if func_name == "search_symbols":
        from codesight_mcp.tools.search_symbols import search_symbols as fn
    elif func_name == "search_text":
        from codesight_mcp.tools.search_text import search_text as fn
    elif func_name == "get_file_outline":
        from codesight_mcp.tools.get_file_outline import get_file_outline as fn
    elif func_name == "get_repo_outline":
        from codesight_mcp.tools.get_repo_outline import get_repo_outline as fn
    elif func_name == "get_symbol":
        from codesight_mcp.tools.get_symbol import get_symbol as fn
    elif func_name == "analyze_complexity":
        from codesight_mcp.tools.analyze_complexity import analyze_complexity as fn
    else:
        raise ValueError(f"Unknown function: {func_name}")

    call_kwargs = {**kwargs, "storage_path": storage_path}
    start = time.perf_counter()
    result = fn(**call_kwargs)
    elapsed = (time.perf_counter() - start) * 1000
    return result, elapsed


def run_cold_query(func_name: str, kwargs: dict, storage_path: str) -> float:
    """Run a query in a fresh subprocess to measure cold-cache latency."""
    import base64
    # Encode kwargs as base64 to avoid quoting issues
    kwargs_b64 = base64.b64encode(json.dumps(kwargs).encode()).decode()
    storage_b64 = base64.b64encode(storage_path.encode()).decode()
    func_b64 = base64.b64encode(func_name.encode()).decode()
    script = f"""
import base64, json, time, sys
sys.path.insert(0, '.')

kwargs = json.loads(base64.b64decode('{kwargs_b64}').decode())
kwargs['storage_path'] = base64.b64decode('{storage_b64}').decode()
func_name = base64.b64decode('{func_b64}').decode()

FUNCS = {{
    'search_symbols': 'codesight_mcp.tools.search_symbols',
    'search_text': 'codesight_mcp.tools.search_text',
    'get_file_outline': 'codesight_mcp.tools.get_file_outline',
    'get_repo_outline': 'codesight_mcp.tools.get_repo_outline',
    'get_symbol': 'codesight_mcp.tools.get_symbol',
    'analyze_complexity': 'codesight_mcp.tools.analyze_complexity',
}}
import importlib
mod = importlib.import_module(FUNCS[func_name])
fn = getattr(mod, func_name)

start = time.perf_counter()
result = fn(**kwargs)
elapsed_ms = (time.perf_counter() - start) * 1000
print(f"{{elapsed_ms:.1f}}")
if 'error' in result:
    print(f"ERROR: {{result['error']}}", file=sys.stderr)
"""
    env = {**os.environ}
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True, text=True,
        cwd=Path(__file__).resolve().parent.parent,
        env=env,
    )
    if result.returncode != 0:
        print(f"  Cold subprocess error: {result.stderr.strip()}", file=sys.stderr)
        return -1.0
    try:
        return float(result.stdout.strip().split("\n")[0])
    except (ValueError, IndexError):
        print(f"  Cold subprocess output: {result.stdout.strip()}", file=sys.stderr)
        return -1.0


# ---------------------------------------------------------------------------
# Main benchmark
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("codesight-mcp Latency Benchmark")
    print("=" * 60)
    print()

    # Environment metadata
    codesight_commit = get_codesight_commit()
    env_info = {
        "python_version": platform.python_version(),
        "platform": f"{platform.system()} {platform.machine()}",
        "codesight_commit": codesight_commit,
        "flask_tag": FLASK_TAG,
    }
    print(f"Python:    {env_info['python_version']}")
    print(f"Platform:  {env_info['platform']}")
    print(f"Codesight: {env_info['codesight_commit']}")
    print()

    # Create isolated temp directories
    work_dir = Path(tempfile.mkdtemp(prefix="codesight-benchmark-"))
    flask_dir = work_dir / "flask"
    storage_path = str(work_dir / "index-storage")
    os.makedirs(storage_path, exist_ok=True)

    try:
        # Step 1: Clone Flask
        print(f"Cloning Flask {FLASK_TAG}...")
        flask_sha = clone_flask(flask_dir)
        env_info["flask_sha"] = flask_sha
        print(f"Flask SHA:  {flask_sha}")

        py_count, loc_count = count_python_files(flask_dir)
        env_info["flask_py_files"] = py_count
        env_info["flask_loc"] = loc_count
        print(f"Corpus:    {py_count} Python files, {loc_count} LOC")
        print()

        # Step 2: Index Flask
        print("Indexing Flask...")
        # Set allowed roots for security gate
        os.environ["CODESIGHT_ALLOWED_ROOTS"] = str(flask_dir)
        from codesight_mcp.tools.index_folder import index_folder
        idx_start = time.perf_counter()
        idx_result = index_folder(
            path=str(flask_dir),
            use_ai_summaries=False,
            storage_path=storage_path,
            allowed_roots=[str(flask_dir)],
        )
        idx_time = (time.perf_counter() - idx_start) * 1000
        if not idx_result.get("success", True) or "error" in idx_result:
            print(f"ERROR: Indexing failed: {idx_result.get('error', 'unknown')}")
            sys.exit(1)
        symbols_count = idx_result.get("symbol_count", "?")
        repo_id = idx_result.get("repo", "")
        print(f"Indexed:   {symbols_count} symbols in {idx_time:.0f}ms")
        print(f"Repo ID:   {repo_id}")
        env_info["index_time_ms"] = round(idx_time, 1)
        env_info["symbols_extracted"] = symbols_count
        env_info["repo_id"] = repo_id
        print()

        # Build queries with the actual repo identifier
        QUERIES = make_queries(repo_id)

        # Step 3: Resolve add_url_rule symbol ID
        print("Resolving add_url_rule symbol ID...")
        add_url_rule_id = resolve_add_url_rule_id(storage_path, repo_id)
        print(f"Symbol ID: {add_url_rule_id}")
        # Patch the query kwargs
        for q in QUERIES:
            if q["func"] == "get_symbol":
                q["kwargs"]["symbol_id"] = add_url_rule_id
        print()

        # Step 4: Cold-cache measurements (fresh subprocess per query)
        print("Running cold-cache measurements (fresh subprocess each)...")
        cold_results = {}
        for q in QUERIES:
            cold_ms = run_cold_query(q["func"], q["kwargs"], storage_path)
            cold_results[q["name"]] = round(cold_ms, 1)
            print(f"  {q['name']}: {cold_ms:.1f}ms")
        print()

        # Step 5: Warm-cache measurements
        # Clear caches to start fresh for warm measurement
        from codesight_mcp.tools._common import _clear_shared_stores
        _clear_shared_stores()

        print(f"Running warm-cache measurements ({WARM_RUNS} runs, take median)...")
        # Priming run (populates cache)
        print("  Priming cache...")
        for q in QUERIES:
            run_query(q["func"], q["kwargs"], storage_path)

        warm_results = {}
        for q in QUERIES:
            times = []
            for _ in range(WARM_RUNS):
                _, elapsed = run_query(q["func"], q["kwargs"], storage_path)
                times.append(elapsed)
            median_ms = round(statistics.median(times), 1)
            warm_results[q["name"]] = median_ms
            print(f"  {q['name']}: {median_ms:.1f}ms (runs: {[round(t, 1) for t in times]})")
        print()

        # Step 6: Cache stats
        from codesight_mcp.tools._common import _get_shared_store
        store = _get_shared_store(storage_path)
        try:
            stats = store.cache_stats()
            if callable(stats):
                stats = stats()
            print(f"Cache stats: {stats}")
        except (TypeError, AttributeError):
            print("Cache stats: unavailable")
        print()

        # Step 7: Compile results
        cold_avg = round(statistics.mean(cold_results.values()), 1)
        warm_avg = round(statistics.mean(warm_results.values()), 1)
        baseline_avg = round(statistics.mean(BASELINE.values()), 1)

        results = {
            "environment": env_info,
            "baseline": BASELINE,
            "cold_cache": cold_results,
            "warm_cache": warm_results,
            "summary": {
                "baseline_avg_ms": baseline_avg,
                "cold_avg_ms": cold_avg,
                "warm_avg_ms": warm_avg,
                "cold_improvement": f"{baseline_avg / cold_avg:.1f}x" if cold_avg > 0 else "N/A",
                "warm_improvement": f"{baseline_avg / warm_avg:.1f}x" if warm_avg > 0 else "N/A",
            },
        }

        # Write JSON
        json_path = "/tmp/benchmark-results.json"
        with open(json_path, "w") as f:
            json.dump(results, f, indent=2)
        print(f"JSON results written to {json_path}")
        print()

        # Step 8: Print markdown table
        print("## Latency Results (ms)")
        print()
        print("| Query | Baseline (2026-04-04) | Cold Cache | Warm Cache |")
        print("|-------|-----------------------|------------|------------|")
        for q in QUERIES:
            name = q["name"]
            base = BASELINE.get(name, "N/A")
            cold = cold_results.get(name, "N/A")
            warm = warm_results.get(name, "N/A")
            print(f"| {name} | {base} | {cold} | {warm} |")
        print(f"| **Average** | **{baseline_avg}** | **{cold_avg}** | **{warm_avg}** |")
        print()
        print(f"Cold improvement: {results['summary']['cold_improvement']} faster than baseline")
        print(f"Warm improvement: {results['summary']['warm_improvement']} faster than baseline")
        print(f"Hypothesis was: ~20ms warm — Actual: {warm_avg}ms")

    finally:
        # Cleanup
        shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
