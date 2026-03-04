"""Tests for get_repo_outline (TEST-MED-2)."""

import pytest

from ironmunch.storage import IndexStore, CodeIndex
from ironmunch.parser import Symbol
from ironmunch.tools.get_repo_outline import get_repo_outline


def _make_store_with_index(
    tmp_path,
    owner: str = "testowner",
    name: str = "testrepo",
    files: list[str] | None = None,
    symbols: list[Symbol] | None = None,
    languages: dict[str, int] | None = None,
) -> IndexStore:
    """Create an IndexStore in tmp_path and save a minimal index."""
    if files is None:
        files = ["src/main.py"]
    if symbols is None:
        symbols = []
    if languages is None:
        languages = {"python": len(files)}

    store = IndexStore(base_path=str(tmp_path))
    raw_files = {f: "# placeholder" for f in files}
    store.save_index(
        owner=owner,
        name=name,
        source_files=files,
        symbols=symbols,
        raw_files=raw_files,
        languages=languages,
    )
    return store


# ---------------------------------------------------------------------------
# 1. Basic structure — expected keys in response
# ---------------------------------------------------------------------------

def test_basic_structure(tmp_path):
    """Response must contain all expected top-level keys."""
    _make_store_with_index(tmp_path)

    result = get_repo_outline("testowner/testrepo", storage_path=str(tmp_path))

    assert "error" not in result, f"Unexpected error: {result.get('error')}"
    for key in ("repo", "indexed_at", "file_count", "symbol_count", "languages", "directories", "_meta"):
        assert key in result, f"Missing key: {key}"

    assert result["repo"] == "testowner/testrepo"
    assert result["file_count"] == 1
    assert result["symbol_count"] == 0
    assert isinstance(result["languages"], dict)
    assert isinstance(result["directories"], dict)
    assert isinstance(result["_meta"], dict)


# ---------------------------------------------------------------------------
# 2. Unknown repo — error response
# ---------------------------------------------------------------------------

def test_unknown_repo(tmp_path):
    """Requesting a repo that was never indexed must return an error dict."""
    result = get_repo_outline("nobody/doesnotexist", storage_path=str(tmp_path))

    assert "error" in result
    assert "nobody/doesnotexist" in result["error"]


# ---------------------------------------------------------------------------
# 3. Root-level files appear in directories under "(root)"
# ---------------------------------------------------------------------------

def test_root_level_files(tmp_path):
    """Files not in subdirectories should appear under the '(root)' key in directories."""
    _make_store_with_index(
        tmp_path,
        files=["README.md", "setup.py"],
        languages={"python": 1},
    )

    result = get_repo_outline("testowner/testrepo", storage_path=str(tmp_path))

    assert "error" not in result
    directories = result["directories"]
    assert "(root)" in directories, f"Expected '(root)' in directories, got: {list(directories.keys())}"
    assert directories["(root)"] == 2


# ---------------------------------------------------------------------------
# 4. Subdirectory files grouped by top-level directory
# ---------------------------------------------------------------------------

def test_subdirectory_grouping(tmp_path):
    """Files in subdirectories should be grouped by their top-level directory."""
    _make_store_with_index(
        tmp_path,
        files=["src/a.py", "src/b.py", "tests/test_a.py"],
        languages={"python": 3},
    )

    result = get_repo_outline("testowner/testrepo", storage_path=str(tmp_path))

    assert "error" not in result
    directories = result["directories"]
    assert directories.get("src/") == 2
    assert directories.get("tests/") == 1
