"""Tests for metadata sidecar files written alongside indexes."""

import json
import pytest
from pathlib import Path
from unittest.mock import patch

from codesight_mcp.storage import IndexStore, CodeIndex
from codesight_mcp.parser import Symbol


def _make_symbol(name="foo"):
    return Symbol(
        id=f"test-py::{name}",
        file="test.py",
        name=name,
        qualified_name=name,
        kind="function",
        language="python",
        signature=f"def {name}():",
        summary=f"Does {name}",
        byte_offset=0,
        byte_length=100,
    )


def _save_simple_index(store, owner="testowner", name="testrepo"):
    return store.save_index(
        owner=owner,
        name=name,
        source_files=["test.py"],
        symbols=[_make_symbol()],
        raw_files={"test.py": "def foo(): pass"},
        languages={"python": 1},
    )


class TestSidecarCreatedOnSave:
    def test_save_index_creates_sidecar(self, tmp_path):
        store = IndexStore(base_path=str(tmp_path))
        _save_simple_index(store)

        meta_path = tmp_path / "testowner__testrepo.meta.json"
        assert meta_path.exists()

        data = json.loads(meta_path.read_text())
        assert data["repo"] == "testowner/testrepo"
        assert data["symbol_count"] == 1
        assert data["file_count"] == 1
        assert data["languages"] == {"python": 1}
        assert data["index_version"] == 2
        assert "indexed_at" in data

    def test_incremental_save_updates_sidecar(self, tmp_path):
        store = IndexStore(base_path=str(tmp_path))
        _save_simple_index(store)

        bar = Symbol(
            id="bar-py::bar",
            file="bar.py",
            name="bar",
            qualified_name="bar",
            kind="function",
            language="python",
            signature="def bar():",
            summary="Does bar",
            byte_offset=0,
            byte_length=50,
        )
        store.incremental_save(
            owner="testowner",
            name="testrepo",
            changed_files=[],
            new_files=["bar.py"],
            deleted_files=[],
            new_symbols=[bar],
            raw_files={"bar.py": "def bar(): pass"},
            languages={"python": 2},
        )

        meta_path = tmp_path / "testowner__testrepo.meta.json"
        data = json.loads(meta_path.read_text())
        assert data["symbol_count"] == 2
        assert data["file_count"] == 2
        assert data["languages"] == {"python": 2}


class TestListReposUsesSidecar:
    def test_list_repos_reads_sidecar(self, tmp_path):
        store = IndexStore(base_path=str(tmp_path))
        _save_simple_index(store)

        repos = store.list_repos()
        assert len(repos) == 1
        assert repos[0]["repo"] == "testowner/testrepo"
        assert repos[0]["symbol_count"] == 1

    def test_list_repos_skips_full_index_when_sidecar_exists(self, tmp_path):
        store = IndexStore(base_path=str(tmp_path))
        _save_simple_index(store)

        with patch.object(store, "_read_metadata_sidecar", wraps=store._read_metadata_sidecar) as mock_meta:
            repos = store.list_repos()

        assert len(repos) == 1
        # Sidecar was read — repo already in seen_repos, so full index is skipped
        mock_meta.assert_called_once()

    def test_list_repos_falls_back_without_sidecar(self, tmp_path):
        store = IndexStore(base_path=str(tmp_path))
        _save_simple_index(store)

        # Remove sidecar to force fallback
        meta_path = tmp_path / "testowner__testrepo.meta.json"
        meta_path.unlink()

        repos = store.list_repos()
        assert len(repos) == 1
        assert repos[0]["repo"] == "testowner/testrepo"


class TestDeleteIndexRemovesSidecar:
    def test_delete_removes_sidecar(self, tmp_path):
        store = IndexStore(base_path=str(tmp_path))
        _save_simple_index(store)

        meta_path = tmp_path / "testowner__testrepo.meta.json"
        assert meta_path.exists()

        store.delete_index("testowner", "testrepo")
        assert not meta_path.exists()

    def test_delete_works_without_sidecar(self, tmp_path):
        store = IndexStore(base_path=str(tmp_path))
        _save_simple_index(store)

        # Remove sidecar first
        (tmp_path / "testowner__testrepo.meta.json").unlink()

        # delete_index should still work
        assert store.delete_index("testowner", "testrepo")


class TestSidecarValidation:
    def test_corrupt_sidecar_falls_back_to_index(self, tmp_path):
        store = IndexStore(base_path=str(tmp_path))
        _save_simple_index(store)

        # Corrupt the sidecar
        meta_path = tmp_path / "testowner__testrepo.meta.json"
        meta_path.write_text("not json")

        repos = store.list_repos()
        assert len(repos) == 1
        assert repos[0]["repo"] == "testowner/testrepo"

    def test_incomplete_sidecar_falls_back_to_index(self, tmp_path):
        store = IndexStore(base_path=str(tmp_path))
        _save_simple_index(store)

        # Write sidecar missing required fields
        meta_path = tmp_path / "testowner__testrepo.meta.json"
        meta_path.write_text(json.dumps({"repo": "testowner/testrepo"}))

        repos = store.list_repos()
        assert len(repos) == 1
        assert repos[0]["repo"] == "testowner/testrepo"
