"""Tests for get_repo_outline (TEST-MED-2) and spotlighting (ADV-HIGH-3)."""

import pytest

from codesight_mcp.storage import IndexStore, CodeIndex
from codesight_mcp.parser import Symbol
from codesight_mcp.tools.get_repo_outline import get_repo_outline


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
    """Files not in subdirectories should appear under a wrapped '(root)' key."""
    _make_store_with_index(
        tmp_path,
        files=["README.md", "setup.py"],
        languages={"python": 1},
    )

    result = get_repo_outline("testowner/testrepo", storage_path=str(tmp_path))

    assert "error" not in result
    directories = result["directories"]
    # All keys are now wrapped — find the one whose unwrapped value is "(root)"
    root_key = next(
        (k for k in directories if _unwrap_dir_key(k) == "(root)"), None
    )
    assert root_key is not None, (
        f"Expected wrapped '(root)' key in directories, got: {list(directories.keys())}"
    )
    assert directories[root_key] == 2


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
    # Unwrap keys to find counts
    unwrapped = {_unwrap_dir_key(k): v for k, v in directories.items()}
    assert unwrapped.get("src/") == 2
    assert unwrapped.get("tests/") == 1


# ---------------------------------------------------------------------------
# 5. ADV-HIGH-3: directory keys spotlighted and trusted=False
# ---------------------------------------------------------------------------

def _unwrap_dir_key(wrapped: str) -> str:
    """Extract inner content from a wrap_untrusted_content() wrapper."""
    lines = wrapped.split("\n")
    return "\n".join(lines[1:-1])


class TestGetRepoOutlineSpotlighting:
    """ADV-HIGH-3: directory keys in get_repo_outline must be spotlighted."""

    def test_directory_keys_are_wrapped(self, tmp_path):
        """Every key in the 'directories' dict must start with <<<UNTRUSTED_CODE_."""
        _make_store_with_index(
            tmp_path,
            files=["src/main.py", "tests/test_main.py"],
            languages={"python": 2},
        )
        result = get_repo_outline("testowner/testrepo", storage_path=str(tmp_path))

        assert "error" not in result
        directories = result["directories"]
        assert len(directories) > 0
        for key in directories:
            assert key.startswith("<<<UNTRUSTED_CODE_"), (
                f"Directory key not wrapped in spotlighting markers: {key!r}"
            )

    def test_injection_dirname_key_is_wrapped(self, tmp_path):
        """A top-level directory with an injection-phrase name must be wrapped."""
        _make_store_with_index(
            tmp_path,
            files=["IGNORE_PREVIOUS/evil.py"],
            languages={"python": 1},
        )
        result = get_repo_outline("testowner/testrepo", storage_path=str(tmp_path))

        assert "error" not in result
        directories = result["directories"]
        assert len(directories) == 1
        key = list(directories.keys())[0]
        assert key.startswith("<<<UNTRUSTED_CODE_"), (
            f"Injection dirname key not wrapped: {key!r}"
        )
        assert _unwrap_dir_key(key) == "IGNORE_PREVIOUS/"

    def test_root_key_is_wrapped(self, tmp_path):
        """The special '(root)' key must also be wrapped."""
        _make_store_with_index(
            tmp_path,
            files=["README.md"],
            languages={"python": 0},
        )
        result = get_repo_outline("testowner/testrepo", storage_path=str(tmp_path))

        assert "error" not in result
        directories = result["directories"]
        for key in directories:
            assert key.startswith("<<<UNTRUSTED_CODE_"), (
                f"'(root)' key not wrapped: {key!r}"
            )

    def test_meta_trusted_is_false(self, tmp_path):
        """_meta['contentTrust'] must be 'untrusted' for get_repo_outline responses."""
        _make_store_with_index(tmp_path)
        result = get_repo_outline("testowner/testrepo", storage_path=str(tmp_path))

        assert "error" not in result
        assert result["_meta"]["contentTrust"] == "untrusted", (
            f"Expected contentTrust='untrusted', got: {result['_meta'].get('contentTrust')!r}"
        )
