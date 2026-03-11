"""Tests for list_repos tool."""

import pytest

from codesight_mcp.tools.list_repos import list_repos
from codesight_mcp.storage import IndexStore
from codesight_mcp.parser import Symbol


def _index_repo(tmp_path, owner, name, files=None, symbols=None):
    """Create a minimal indexed repo."""
    if files is None:
        files = ["main.py"]
    if symbols is None:
        symbols = []

    store = IndexStore(base_path=str(tmp_path))
    raw_files = {f: "# content\n" for f in files}
    store.save_index(
        owner=owner,
        name=name,
        source_files=files,
        symbols=symbols,
        raw_files=raw_files,
        languages={"python": len(files)},
    )
    return store


class TestListReposHappyPath:
    """Happy-path tests for list_repos."""

    def test_returns_empty_when_no_repos(self, tmp_path):
        """An empty storage directory should return count=0."""
        result = list_repos(storage_path=str(tmp_path))

        assert result["count"] == 0
        assert result["repos"] == []
        assert "_meta" in result

    def test_returns_single_repo(self, tmp_path):
        """Should list one repo after indexing it."""
        _index_repo(tmp_path, "owner", "myrepo")
        result = list_repos(storage_path=str(tmp_path))

        assert result["count"] == 1
        assert len(result["repos"]) == 1
        repo = result["repos"][0]
        assert "owner/myrepo" in repo["repo"]
        assert repo["file_count"] == 1
        assert "indexed_at" in repo

    def test_returns_multiple_repos(self, tmp_path):
        """Should list all indexed repos."""
        _index_repo(tmp_path, "org", "alpha")
        _index_repo(tmp_path, "org", "beta", files=["a.py", "b.py"])
        result = list_repos(storage_path=str(tmp_path))

        assert result["count"] == 2
        repo_names = {r["repo"] for r in result["repos"]}
        # Names are wrapped, so check containment
        assert any("alpha" in name for name in repo_names)
        assert any("beta" in name for name in repo_names)

    def test_symbol_count_in_listing(self, tmp_path):
        """Repos with symbols should report the correct symbol_count."""
        sym = Symbol(
            id="main.py::run#function",
            file="main.py",
            name="run",
            qualified_name="run",
            kind="function",
            language="python",
            signature="def run():",
            summary="Run it",
            byte_offset=0, byte_length=10,
        )
        _index_repo(tmp_path, "local", "proj", symbols=[sym])
        result = list_repos(storage_path=str(tmp_path))

        assert result["count"] == 1
        assert result["repos"][0]["symbol_count"] == 1


class TestListReposMeta:
    """Tests for _meta envelope on list_repos."""

    def test_meta_has_timing(self, tmp_path):
        """_meta should include timing_ms."""
        result = list_repos(storage_path=str(tmp_path))
        assert "timing_ms" in result["_meta"]

    def test_meta_trusted_is_untrusted(self, tmp_path):
        """list_repos wraps disk-derived repo names, so contentTrust should be untrusted."""
        result = list_repos(storage_path=str(tmp_path))
        assert result["_meta"]["contentTrust"] == "untrusted"


class TestListReposEdgeCases:
    """Edge-case tests for list_repos."""

    def test_repo_names_are_wrapped(self, tmp_path):
        """Repo names should be wrapped with untrusted content markers."""
        _index_repo(tmp_path, "owner", "myrepo")
        result = list_repos(storage_path=str(tmp_path))

        repo_name = result["repos"][0]["repo"]
        assert repo_name.startswith("<<<UNTRUSTED_CODE_")

    def test_languages_included(self, tmp_path):
        """Each repo entry should include language breakdown."""
        _index_repo(tmp_path, "local", "demo")
        result = list_repos(storage_path=str(tmp_path))

        assert "languages" in result["repos"][0]
        assert result["repos"][0]["languages"]["python"] >= 1

    def test_index_version_included(self, tmp_path):
        """Each repo entry should include the index version."""
        _index_repo(tmp_path, "local", "demo")
        result = list_repos(storage_path=str(tmp_path))

        assert "index_version" in result["repos"][0]
