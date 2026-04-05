"""Tests for shared IndexStore factory and cache race fix.

Verifies that:
- _get_shared_store returns the same instance for the same storage_path
- RepoContext.resolve() and parse_repo() share the IndexStore instance
- Cache hits occur on second load via the shared store
- _cache_misses is incremented correctly (inside the lock)
- Cache invalidation via save_index and delete_index
- Thread safety under concurrent loads
"""

import gzip
import json
import threading
from pathlib import Path

import pytest

from codesight_mcp.parser import Symbol
from codesight_mcp.storage.index_store import INDEX_VERSION, IndexStore
from codesight_mcp.tools._common import (
    RepoContext,
    _clear_shared_stores,
    _get_shared_store,
    parse_repo,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_valid_index_dict(
    owner: str = "testowner",
    name: str = "testrepo",
) -> dict:
    """Build a valid index dict suitable for serialization."""
    return {
        "repo": f"{owner}/{name}",
        "owner": owner,
        "name": name,
        "indexed_at": "2026-01-01T00:00:00+00:00",
        "source_files": ["src/main.py"],
        "languages": {"python": 1},
        "symbols": [
            {
                "id": "src/main.py::func_a#function",
                "file": "src/main.py",
                "name": "func_a",
                "qualified_name": "func_a",
                "kind": "function",
                "language": "python",
                "signature": "def func_a()",
                "docstring": "",
                "summary": "A test function",
                "decorators": [],
                "keywords": ["test"],
                "parent": None,
                "line": 1,
                "end_line": 5,
                "byte_offset": 0,
                "byte_length": 20,
                "content_hash": "a" * 64,
                "calls": [],
                "imports": [],
                "inherits_from": [],
                "implements": [],
                "complexity": {},
            }
        ],
        "index_version": INDEX_VERSION,
        "file_hashes": {"src/main.py": "a" * 64},
        "git_head": "",
    }


def _write_gzip_index(path: Path, data: dict) -> None:
    """Write a gzip-compressed JSON index to path."""
    json_bytes = json.dumps(data).encode("utf-8")
    compressed = gzip.compress(json_bytes, compresslevel=6)
    path.write_bytes(compressed)


@pytest.fixture(autouse=True)
def _clear_stores():
    """Clear shared store cache before each test to prevent cross-test contamination."""
    _clear_shared_stores()
    yield
    _clear_shared_stores()


# ===========================================================================
# Shared store factory tests
# ===========================================================================


class TestSharedStoreFactory:
    """Tests for _get_shared_store singleton behavior."""

    def test_shared_store_same_path(self, tmp_path: Path) -> None:
        """Same storage_path returns the same IndexStore instance."""
        path = str(tmp_path)
        store_a = _get_shared_store(path)
        store_b = _get_shared_store(path)
        assert store_a is store_b

    def test_shared_store_different_paths(self, tmp_path: Path) -> None:
        """Different storage_paths return different IndexStore instances."""
        path_a = str(tmp_path / "a")
        path_b = str(tmp_path / "b")
        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        store_a = _get_shared_store(path_a)
        store_b = _get_shared_store(path_b)
        assert store_a is not store_b


# ===========================================================================
# RepoContext and parse_repo sharing tests
# ===========================================================================


class TestRepoContextSharesStore:
    """Two RepoContext.resolve() calls with the same storage_path share a store."""

    def test_repo_context_shares_store(self, tmp_path: Path) -> None:
        """RepoContext.resolve() returns the shared store instance."""
        data = _make_valid_index_dict()
        _write_gzip_index(tmp_path / "testowner__testrepo.json.gz", data)

        ctx_a = RepoContext.resolve("testowner/testrepo", storage_path=str(tmp_path))
        ctx_b = RepoContext.resolve("testowner/testrepo", storage_path=str(tmp_path))

        assert not isinstance(ctx_a, dict), f"resolve failed: {ctx_a}"
        assert not isinstance(ctx_b, dict), f"resolve failed: {ctx_b}"
        assert ctx_a.store is ctx_b.store

    def test_parse_repo_shares_store(self, tmp_path: Path) -> None:
        """parse_repo() with bare name uses the shared store."""
        data = _make_valid_index_dict()
        _write_gzip_index(tmp_path / "testowner__testrepo.json.gz", data)

        # parse_repo with bare name triggers IndexStore creation internally
        owner, name = parse_repo("testrepo", storage_path=str(tmp_path))
        assert owner == "testowner"
        assert name == "testrepo"

        # Now resolve via RepoContext — should get the same shared store
        ctx = RepoContext.resolve("testowner/testrepo", storage_path=str(tmp_path))
        assert not isinstance(ctx, dict), f"resolve failed: {ctx}"

        # Both paths should have used the same shared store
        shared = _get_shared_store(str(tmp_path))
        assert ctx.store is shared


# ===========================================================================
# Cache behavior tests
# ===========================================================================


class TestCacheBehavior:
    """Tests for cache hits/misses via the shared store."""

    def test_cache_hit_on_second_load(self, tmp_path: Path) -> None:
        """Second load_index on the same repo produces a cache hit."""
        data = _make_valid_index_dict()
        _write_gzip_index(tmp_path / "testowner__testrepo.json.gz", data)

        store = _get_shared_store(str(tmp_path))

        # First load — cache miss
        index_1 = store.load_index("testowner", "testrepo")
        assert index_1 is not None
        assert store.cache_stats["misses"] == 1
        assert store.cache_stats["hits"] == 0

        # Second load — cache hit
        index_2 = store.load_index("testowner", "testrepo")
        assert index_2 is not None
        assert store.cache_stats["hits"] == 1

    def test_cache_misses_under_lock(self, tmp_path: Path) -> None:
        """Verify _cache_misses is incremented correctly on first load."""
        data = _make_valid_index_dict()
        _write_gzip_index(tmp_path / "testowner__testrepo.json.gz", data)

        store = _get_shared_store(str(tmp_path))

        # Before any load
        assert store.cache_stats["misses"] == 0

        # First load — exactly one miss
        index = store.load_index("testowner", "testrepo")
        assert index is not None
        assert store.cache_stats["misses"] == 1

        # Second load — miss count stays at 1 (hit, not miss)
        store.load_index("testowner", "testrepo")
        assert store.cache_stats["misses"] == 1
        assert store.cache_stats["hits"] == 1


# ===========================================================================
# Cache invalidation tests
# ===========================================================================


def _make_symbol(name: str = "func_a") -> Symbol:
    """Build a minimal Symbol for use with save_index."""
    return Symbol(
        id=f"src/main.py::{name}#function",
        file="src/main.py",
        name=name,
        qualified_name=name,
        kind="function",
        language="python",
        signature=f"def {name}()",
        line=1,
    )


class TestCacheInvalidation:
    """Tests that save_index and delete_index evict the LRU cache."""

    def test_save_index_evicts_cache(self, tmp_path: Path) -> None:
        """save_index for a cached repo evicts the entry so next load is a miss."""
        data = _make_valid_index_dict()
        _write_gzip_index(tmp_path / "testowner__testrepo.json.gz", data)

        store = _get_shared_store(str(tmp_path))

        # First load — cache miss
        index_1 = store.load_index("testowner", "testrepo")
        assert index_1 is not None
        assert store.cache_stats["misses"] == 1

        # Second load — cache hit
        index_2 = store.load_index("testowner", "testrepo")
        assert index_2 is not None
        assert store.cache_stats["hits"] == 1

        misses_before_save = store.cache_stats["misses"]

        # Save a new index — should evict the cache entry
        store.save_index(
            owner="testowner",
            name="testrepo",
            source_files=["src/main.py"],
            symbols=[_make_symbol("func_b")],
            raw_files={"src/main.py": "def func_b(): pass"},
            languages={"python": 1},
        )

        # Load again — should be a cache miss (evicted by save_index)
        index_3 = store.load_index("testowner", "testrepo")
        assert index_3 is not None
        assert store.cache_stats["misses"] == misses_before_save + 1

    def test_delete_index_evicts_cache(self, tmp_path: Path) -> None:
        """delete_index removes the cache entry; subsequent load returns None."""
        data = _make_valid_index_dict()
        _write_gzip_index(tmp_path / "testowner__testrepo.json.gz", data)

        store = _get_shared_store(str(tmp_path))

        # Load twice: miss then hit
        index_1 = store.load_index("testowner", "testrepo")
        assert index_1 is not None
        assert store.cache_stats["misses"] == 1

        index_2 = store.load_index("testowner", "testrepo")
        assert index_2 is not None
        assert store.cache_stats["hits"] == 1

        # Delete the index — evicts cache and removes file
        deleted = store.delete_index("testowner", "testrepo")
        assert deleted is True

        # Load again — index file is gone, should return None
        index_3 = store.load_index("testowner", "testrepo")
        assert index_3 is None


# ===========================================================================
# Thread safety tests
# ===========================================================================


class TestThreadSafety:
    """Tests that concurrent access to the shared store is safe."""

    def test_concurrent_loads_no_exceptions(self, tmp_path: Path) -> None:
        """10 concurrent threads loading the same index raise no exceptions."""
        data = _make_valid_index_dict()
        _write_gzip_index(tmp_path / "testowner__testrepo.json.gz", data)

        # Write the content file that save_index would have written
        content_dir = tmp_path / "testowner__testrepo_content" / "src"
        content_dir.mkdir(parents=True)
        (content_dir / "main.py").write_text("def func_a(): pass")

        store = _get_shared_store(str(tmp_path))
        thread_count = 10
        results: list = [None] * thread_count
        errors: list[Exception] = []

        def load_in_thread(idx: int) -> None:
            try:
                results[idx] = store.load_index("testowner", "testrepo")
            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=load_in_thread, args=(i,))
            for i in range(thread_count)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert not errors, f"Exceptions in threads: {errors}"
        assert all(result is not None for result in results)
