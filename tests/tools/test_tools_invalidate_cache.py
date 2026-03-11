"""Functional tests for the invalidate_cache tool."""

import json
import tempfile
from pathlib import Path
import pytest
from codesight_mcp.storage.index_store import IndexStore
from codesight_mcp.tools.invalidate_cache import invalidate_cache


def _make_store_with_repo(storage_path: str) -> None:
    """Helper to create an indexed repo in storage."""
    store = IndexStore(storage_path)
    store.save_index(
        owner="test", name="repo",
        source_files=["main.py"],
        symbols=[],
        raw_files={"main.py": "x = 1"},
        languages={"python": 1},
    )


def test_invalidate_cache_existing_repo(tmp_path):
    """invalidate_cache returns success: True and removes the index."""
    _make_store_with_repo(str(tmp_path))
    store = IndexStore(str(tmp_path))
    assert store.load_index("test", "repo") is not None

    result = invalidate_cache("test/repo", storage_path=str(tmp_path), confirm=True)
    assert result["success"] is True
    assert store.load_index("test", "repo") is None


def test_invalidate_cache_nonexistent_repo(tmp_path):
    """invalidate_cache returns success: False for a repo that doesn't exist."""
    result = invalidate_cache("owner/doesnotexist", storage_path=str(tmp_path), confirm=True)
    assert result["success"] is False
    assert "error" in result


def test_invalidate_cache_removes_content_dir(tmp_path):
    """invalidate_cache removes the content directory alongside the JSON."""
    _make_store_with_repo(str(tmp_path))
    # Content dir name uses __ separator
    content_dirs = [d for d in tmp_path.iterdir() if d.is_dir() and "test" in d.name]
    assert len(content_dirs) > 0, "Content directory should exist after indexing"

    result = invalidate_cache("test/repo", storage_path=str(tmp_path), confirm=True)
    assert result["success"] is True
    remaining_dirs = [d for d in tmp_path.iterdir() if d.is_dir() and "test" in d.name]
    assert len(remaining_dirs) == 0, "Content directory should be gone after invalidation"


def test_invalidate_cache_without_confirm_returns_error_dict(tmp_path):
    """ADV-MED-13: invalidate_cache without confirm=True must return error dict."""
    _make_store_with_repo(str(tmp_path))
    result = invalidate_cache("test/repo", storage_path=str(tmp_path))
    assert "error" in result
    assert "confirm=True" in result["error"]


def test_invalidate_cache_with_confirm_true_deletes_index(tmp_path):
    """ADV-MED-13: invalidate_cache with confirm=True must succeed and delete the index."""
    _make_store_with_repo(str(tmp_path))
    store = IndexStore(str(tmp_path))
    assert store.load_index("test", "repo") is not None

    result = invalidate_cache("test/repo", storage_path=str(tmp_path), confirm=True)
    assert result["success"] is True
    assert store.load_index("test", "repo") is None
