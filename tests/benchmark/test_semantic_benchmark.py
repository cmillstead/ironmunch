"""Semantic search performance benchmarks.

Run with: RUN_BENCHMARKS=1 .venv/bin/pytest tests/benchmark/test_semantic_benchmark.py -v -m benchmark
Skipped by default to avoid slowing normal test runs.
"""

import glob
import importlib.util
import os
import tempfile
import time

import pytest

from codesight_mcp.parser.symbols import Symbol
from codesight_mcp.storage.index_store import IndexStore
from codesight_mcp.tools.search_symbols import search_symbols

_HAS_FASTEMBED = importlib.util.find_spec("fastembed") is not None

pytestmark = [
    pytest.mark.benchmark,
    pytest.mark.skipif(not _HAS_FASTEMBED, reason="fastembed not installed (semantic extra)"),
]

if os.environ.get("RUN_BENCHMARKS") != "1":
    pytest.skip("Benchmarks skipped unless RUN_BENCHMARKS=1", allow_module_level=True)


def _make_symbols(count: int) -> list[Symbol]:
    """Generate N unique symbols with distinct summaries."""
    return [
        Symbol(
            id=f"src/mod{i}.py::func{i}#function",
            file=f"src/mod{i}.py",
            name=f"func{i}",
            qualified_name=f"func{i}",
            kind="function",
            language="python",
            signature=f"def func{i}(x: int) -> int:",
            docstring="",
            summary=f"Function number {i} that processes data item {i}",
            decorators=[],
            keywords=[],
            parent=None,
            line=1,
            end_line=5,
            byte_offset=0,
            byte_length=100,
        )
        for i in range(count)
    ]


def _setup_index(tmp: str, count: int) -> None:
    """Create an index with N symbols."""
    symbols = _make_symbols(count)
    raw_files = {f"src/mod{i}.py": f"def func{i}(x): return x" for i in range(count)}
    store = IndexStore(base_path=tmp)
    store.save_index("bench", "repo", list(raw_files.keys()), symbols, raw_files, {"python": count})


def test_embedding_generation_time():
    """Measure embedding generation time for varying symbol counts."""
    for count in [10, 50, 100]:
        tmp = tempfile.mkdtemp()
        _setup_index(tmp, count)

        start = time.perf_counter()
        result = search_symbols(repo="bench/repo", query="process data", storage_path=tmp, semantic=True)
        elapsed = time.perf_counter() - start

        assert "error" not in result, f"Error: {result.get('error')}"
        assert len(result.get("results", [])) > 0
        print(f"\n  Embed + search {count} symbols: {elapsed:.2f}s")


def test_query_latency_keyword_vs_hybrid_vs_semantic():
    """Compare query latency across search modes."""
    tmp = tempfile.mkdtemp()
    _setup_index(tmp, 50)

    # Warm up: generate embeddings first
    search_symbols(repo="bench/repo", query="warmup", storage_path=tmp, semantic=True)

    modes = [
        ("keyword", {}),
        ("hybrid", {"semantic": True}),
        ("semantic_only", {"semantic_only": True}),
    ]
    for mode_name, kwargs in modes:
        times = []
        for _ in range(3):
            start = time.perf_counter()
            result = search_symbols(repo="bench/repo", query="process data", storage_path=tmp, **kwargs)
            times.append(time.perf_counter() - start)
        avg = sum(times) / len(times)
        assert "error" not in result
        print(f"\n  {mode_name}: avg {avg * 1000:.1f}ms")


def test_sidecar_file_size():
    """Measure sidecar file size for N symbols."""
    tmp = tempfile.mkdtemp()
    _setup_index(tmp, 100)

    # Generate embeddings
    result = search_symbols(repo="bench/repo", query="test", storage_path=tmp, semantic=True)
    assert "error" not in result

    sidecars = glob.glob(os.path.join(tmp, "*.embeddings.gz"))
    assert len(sidecars) == 1
    size_kb = os.path.getsize(sidecars[0]) / 1024
    print(f"\n  Sidecar for 100 symbols: {size_kb:.1f} KB")
