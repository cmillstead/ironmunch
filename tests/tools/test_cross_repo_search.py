"""Tests for cross-repo search (Task 17): search_symbols and search_text with repos parameter."""

import tempfile
from pathlib import Path

import pytest

from codesight_mcp.storage.index_store import IndexStore
from codesight_mcp.parser.symbols import Symbol
from codesight_mcp.tools.search_symbols import search_symbols
from codesight_mcp.tools.search_text import search_text


def _make_repo(tmp: str, owner: str, name: str, func_name: str, file_content: str):
    """Create a minimal indexed repo with one function symbol."""
    symbols = [Symbol(
        id=f"src/mod.py::{func_name}#function",
        file="src/mod.py",
        name=func_name,
        qualified_name=func_name,
        kind="function",
        language="python",
        signature=f"def {func_name}():",
        docstring="",
        summary=f"does {func_name}",
        decorators=[],
        keywords=[],
        parent=None,
        line=1, end_line=3,
        byte_offset=0, byte_length=len(file_content),
        content_hash="c" * 64,
    )]
    store = IndexStore(tmp)
    content_dir = Path(tmp) / f"{owner}__{name}"
    content_dir.mkdir(parents=True, exist_ok=True)
    src_dir = content_dir / "src"
    src_dir.mkdir(exist_ok=True)
    (src_dir / "mod.py").write_text(file_content)
    store.save_index(
        owner=owner, name=name,
        source_files=["src/mod.py"],
        symbols=symbols,
        raw_files={"src/mod.py": file_content},
        languages={"python": 1},
    )


class TestSearchSymbolsCrossRepo:
    """Cross-repo search_symbols with repos parameter."""

    def test_single_repo_still_works(self):
        """Existing single-repo search_symbols must still work."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_repo(tmp, "owner", "repo1", "alpha", "def alpha():\n    pass\n")
            result = search_symbols(repo="owner/repo1", query="alpha", storage_path=tmp)
            assert "error" not in result
            assert result["result_count"] >= 1
            assert result["repo"] == "owner/repo1"

    def test_repos_param_searches_multiple(self):
        """repos parameter searches across multiple repos."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_repo(tmp, "owner", "repo1", "alpha", "def alpha():\n    pass\n")
            _make_repo(tmp, "owner", "repo2", "beta", "def beta():\n    pass\n")
            result = search_symbols(
                repos=["owner/repo1", "owner/repo2"],
                query="alpha",
                storage_path=tmp,
            )
            assert "error" not in result
            assert "repos" in result
            assert len(result["repos"]) == 2

    def test_repos_param_merges_results_by_score(self):
        """Results from multiple repos are merged and sorted by score."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_repo(tmp, "owner", "repo1", "alpha", "def alpha():\n    pass\n")
            _make_repo(tmp, "owner", "repo2", "alpha", "def alpha():\n    pass\n")
            result = search_symbols(
                repos=["owner/repo1", "owner/repo2"],
                query="alpha",
                storage_path=tmp,
            )
            assert result["result_count"] == 2
            # Each result should have a repo field
            repos_in_results = {r["repo"] for r in result["results"]}
            assert repos_in_results == {"owner/repo1", "owner/repo2"}

    def test_repos_and_repo_mutually_exclusive(self):
        """Specifying both repo and repos returns an error."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_repo(tmp, "owner", "repo1", "alpha", "def alpha():\n    pass\n")
            result = search_symbols(
                repo="owner/repo1",
                repos=["owner/repo1"],
                query="alpha",
                storage_path=tmp,
            )
            assert "error" in result
            assert "both" in result["error"].lower()

    def test_neither_repo_nor_repos_returns_error(self):
        """Omitting both repo and repos returns an error."""
        with tempfile.TemporaryDirectory() as tmp:
            result = search_symbols(query="alpha", storage_path=tmp)
            assert "error" in result

    def test_max_5_repos(self):
        """More than 5 repos returns an error."""
        with tempfile.TemporaryDirectory() as tmp:
            repos = [f"owner/repo{i}" for i in range(6)]
            result = search_symbols(repos=repos, query="foo", storage_path=tmp)
            assert "error" in result
            assert "5" in result["error"]

    def test_partial_failure_returns_errors(self):
        """If some repos fail, results from successful repos plus errors are returned."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_repo(tmp, "owner", "repo1", "alpha", "def alpha():\n    pass\n")
            result = search_symbols(
                repos=["owner/repo1", "owner/nonexistent"],
                query="alpha",
                storage_path=tmp,
            )
            assert result["result_count"] >= 1
            assert "errors" in result
            assert len(result["errors"]) == 1
            assert result["errors"][0]["repo"] == "owner/nonexistent"

    def test_exactly_5_repos_allowed(self):
        """5 repos is within the limit."""
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(5):
                _make_repo(tmp, "owner", f"repo{i}", f"func{i}", f"def func{i}():\n    pass\n")
            repos = [f"owner/repo{i}" for i in range(5)]
            result = search_symbols(repos=repos, query="func", storage_path=tmp)
            assert "error" not in result
            assert len(result["repos"]) == 5


class TestSearchTextCrossRepo:
    """Cross-repo search_text with repos parameter."""

    def test_single_repo_still_works(self):
        """Existing single-repo search_text must still work."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_repo(tmp, "owner", "repo1", "alpha", "def alpha():\n    return 1\n")
            result = search_text(
                repo="owner/repo1", query="alpha",
                storage_path=tmp,
            )
            assert "error" not in result
            assert result["result_count"] >= 1
            assert result["repo"] == "owner/repo1"

    def test_repos_param_searches_multiple(self):
        """repos parameter searches text across multiple repos."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_repo(tmp, "owner", "repo1", "alpha", "def alpha():\n    return 1\n")
            _make_repo(tmp, "owner", "repo2", "beta", "def beta():\n    return 2\n")
            result = search_text(
                repos=["owner/repo1", "owner/repo2"],
                query="def",
                    storage_path=tmp,
            )
            assert "error" not in result
            assert "repos" in result
            assert result["result_count"] >= 2
            # Each result in multi-repo mode has a repo label
            repos_in_results = {r["repo"] for r in result["results"]}
            assert repos_in_results == {"owner/repo1", "owner/repo2"}

    def test_repos_and_repo_mutually_exclusive(self):
        """Specifying both repo and repos returns an error."""
        result = search_text(
            repo="owner/repo1",
            repos=["owner/repo1"],
            query="foo",
        )
        assert "error" in result
        assert "both" in result["error"].lower()

    def test_neither_repo_nor_repos_returns_error(self):
        """Omitting both repo and repos returns an error."""
        result = search_text(
            query="foo",
        )
        assert "error" in result

    def test_max_5_repos(self):
        """More than 5 repos returns an error."""
        repos = [f"owner/repo{i}" for i in range(6)]
        result = search_text(
            repos=repos, query="foo",
        )
        assert "error" in result
        assert "5" in result["error"]

    def test_partial_failure_returns_errors(self):
        """If some repos fail, results from successful repos plus errors are returned."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_repo(tmp, "owner", "repo1", "alpha", "def alpha():\n    return 1\n")
            result = search_text(
                repos=["owner/repo1", "owner/nonexistent"],
                query="alpha",
                    storage_path=tmp,
            )
            assert result["result_count"] >= 1
            assert "errors" in result
            assert len(result["errors"]) == 1

