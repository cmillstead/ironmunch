"""Tests for the status tool."""

import os

import pytest

from codesight_mcp.tools.status import status
from codesight_mcp.storage import IndexStore, INDEX_VERSION
from codesight_mcp.parser import Symbol


def _index_repo(tmp_path, owner, name, symbols=None):
    """Create a minimal indexed repo."""
    files = ["main.py"]
    if symbols is None:
        symbols = []
    store = IndexStore(base_path=str(tmp_path))
    store.save_index(
        owner=owner,
        name=name,
        source_files=files,
        symbols=symbols,
        raw_files={"main.py": "# content\n"},
        languages={"python": 1},
    )
    return store


class TestStatusHappyPath:
    """Happy-path tests for the status tool."""

    def test_empty_storage(self, tmp_path):
        """Status on empty storage returns zero counts."""
        result = status(storage_path=str(tmp_path))

        assert result["repo_count"] == 0
        assert result["total_symbols"] == 0
        assert result["storage_path"] == str(tmp_path)
        assert result["version"] == INDEX_VERSION
        # ADV-LOW-7: has_api_key removed — must not leak API key presence
        assert "has_api_key" not in result
        assert "_meta" in result

    def test_with_repos(self, tmp_path):
        """Status reflects indexed repos and symbol counts."""
        sym = Symbol(
            id="main.py::run#function",
            file="main.py",
            name="run",
            qualified_name="run",
            kind="function",
            language="python",
            signature="def run():",
            summary="Run it",
            byte_offset=0,
            byte_length=10,
        )
        _index_repo(tmp_path, "org", "alpha", symbols=[sym])
        _index_repo(tmp_path, "org", "beta")

        result = status(storage_path=str(tmp_path))

        assert result["repo_count"] == 2
        assert result["total_symbols"] == 1

    def test_version_matches_constant(self, tmp_path):
        """Version should match INDEX_VERSION."""
        result = status(storage_path=str(tmp_path))
        assert result["version"] == INDEX_VERSION


class TestStatusApiKey:
    """ADV-LOW-7: has_api_key removed — status must not leak API key presence."""

    def test_has_api_key_not_in_response(self, tmp_path, monkeypatch):
        """has_api_key must not appear in the status response."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-key")
        result = status(storage_path=str(tmp_path))
        assert "has_api_key" not in result

    def test_api_key_not_exposed(self, tmp_path, monkeypatch):
        """The actual API key value must never appear in the response."""
        secret = "sk-ant-secret-value-12345"
        monkeypatch.setenv("ANTHROPIC_API_KEY", secret)
        result = status(storage_path=str(tmp_path))

        import json
        serialized = json.dumps(result)
        assert secret not in serialized


class TestStatusMeta:
    """Tests for _meta envelope."""

    def test_meta_has_timing(self, tmp_path):
        """_meta should include timing_ms."""
        result = status(storage_path=str(tmp_path))
        assert "timing_ms" in result["_meta"]

    def test_meta_trusted(self, tmp_path):
        """Status is trusted system data."""
        result = status(storage_path=str(tmp_path))
        assert result["_meta"]["contentTrust"] == "trusted"
