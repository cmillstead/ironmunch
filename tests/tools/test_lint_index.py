"""Tests for the lint_index tool -- deep structural integrity audit."""

import os

import pytest

from codesight_mcp.parser.symbols import Symbol
from codesight_mcp.storage import IndexStore
from codesight_mcp.tools.lint_index import lint_index
from codesight_mcp.tools.registry import get_all_specs


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_store_with_repo(tmp_path, symbols=None, raw_files=None):
    """Create an IndexStore with one indexed repo and return (store, index)."""
    if raw_files is None:
        raw_files = {"test.py": "def func():\n    return 1\n"}
    if symbols is None:
        src = raw_files["test.py"]
        symbols = [
            Symbol(
                id="test.py::func#function",
                file="test.py",
                name="func",
                qualified_name="func",
                kind="function",
                language="python",
                signature="def func():",
                summary="A test function",
                byte_offset=0,
                byte_length=len(src.encode("utf-8")),
            ),
        ]
    store = IndexStore(base_path=str(tmp_path))
    index = store.save_index(
        owner="test",
        name="repo",
        source_files=list(raw_files.keys()),
        symbols=symbols,
        raw_files=raw_files,
        languages={"python": len(raw_files)},
    )
    return store, index


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestLintIndex:
    """Tests for the lint_index tool."""

    def test_clean_index(self, tmp_path):
        """A well-formed index should report clean with no findings."""
        _make_store_with_repo(tmp_path)
        result = lint_index("test/repo", storage_path=str(tmp_path))

        assert result["clean"] is True
        assert result["findings"] == []
        assert result["summary"]["total_findings"] == 0

    def test_clean_index_with_zero_symbol_file(self, tmp_path):
        """A file with no symbols but in source_files should not trigger findings."""
        raw_files = {
            "test.py": "def func():\n    return 1\n",
            "empty.py": "# just a comment\n",
        }
        src = raw_files["test.py"]
        symbols = [
            Symbol(
                id="test.py::func#function",
                file="test.py",
                name="func",
                qualified_name="func",
                kind="function",
                language="python",
                signature="def func():",
                summary="A test function",
                byte_offset=0,
                byte_length=len(src.encode("utf-8")),
            ),
        ]
        _make_store_with_repo(tmp_path, symbols=symbols, raw_files=raw_files)
        result = lint_index("test/repo", storage_path=str(tmp_path))

        assert result["clean"] is True

    def test_orphaned_symbol(self, tmp_path):
        """Deleting a content file should produce an orphaned_symbol finding."""
        _make_store_with_repo(tmp_path)

        content_file = tmp_path / "test__repo" / "test.py"
        os.unlink(content_file)

        result = lint_index("test/repo", storage_path=str(tmp_path))

        finding_types = [f["type"] for f in result["findings"]]
        assert "orphaned_symbol" in finding_types

    def test_orphaned_content(self, tmp_path):
        """A stray file on disk not in the index should produce orphaned_content."""
        _make_store_with_repo(tmp_path)

        stray = tmp_path / "test__repo" / "stray.py"
        stray.write_text("stray")

        result = lint_index("test/repo", storage_path=str(tmp_path))

        finding_types = [f["type"] for f in result["findings"]]
        assert "orphaned_content" in finding_types

    def test_orphaned_content_not_triggered_by_symbolless_file(self, tmp_path):
        """A file in file_hashes but with no symbols should not be orphaned_content."""
        raw_files = {
            "test.py": "def func():\n    return 1\n",
            "empty.py": "# just a comment\n",
        }
        src = raw_files["test.py"]
        symbols = [
            Symbol(
                id="test.py::func#function",
                file="test.py",
                name="func",
                qualified_name="func",
                kind="function",
                language="python",
                signature="def func():",
                summary="A test function",
                byte_offset=0,
                byte_length=len(src.encode("utf-8")),
            ),
        ]
        _make_store_with_repo(tmp_path, symbols=symbols, raw_files=raw_files)
        result = lint_index("test/repo", storage_path=str(tmp_path))

        orphaned_content_findings = [
            f for f in result["findings"] if f["type"] == "orphaned_content"
        ]
        assert orphaned_content_findings == []

    def test_duplicate_symbol(self, tmp_path):
        """Two symbols with same file, name, and kind should produce duplicate_symbol."""
        src = "def func():\n    return 1\ndef func():\n    return 2\n"
        raw_files = {"test.py": src}
        symbols = [
            Symbol(
                id="test.py::func#function",
                file="test.py",
                name="func",
                qualified_name="func",
                kind="function",
                language="python",
                signature="def func():",
                summary="First func",
                byte_offset=0,
                byte_length=20,
            ),
            Symbol(
                id="test.py::func#function:2",
                file="test.py",
                name="func",
                qualified_name="func",
                kind="function",
                language="python",
                signature="def func():",
                summary="Second func",
                byte_offset=21,
                byte_length=20,
            ),
        ]
        _make_store_with_repo(tmp_path, symbols=symbols, raw_files=raw_files)
        result = lint_index("test/repo", storage_path=str(tmp_path))

        dup_findings = [f for f in result["findings"] if f["type"] == "duplicate_symbol"]
        assert len(dup_findings) == 1
        assert dup_findings[0]["count"] == 2

    def test_call_graph_broken_ref(self, tmp_path):
        """A symbol calling a nonexistent callee should produce call_graph_broken_ref."""
        src = "def func():\n    return 1\n"
        raw_files = {"test.py": src}
        symbols = [
            Symbol(
                id="test.py::func#function",
                file="test.py",
                name="func",
                qualified_name="func",
                kind="function",
                language="python",
                signature="def func():",
                summary="A function",
                byte_offset=0,
                byte_length=len(src.encode("utf-8")),
                calls=["test.py::nonexistent#function"],
            ),
        ]
        _make_store_with_repo(tmp_path, symbols=symbols, raw_files=raw_files)
        result = lint_index("test/repo", storage_path=str(tmp_path))

        broken_ref_findings = [
            f for f in result["findings"] if f["type"] == "call_graph_broken_ref"
        ]
        assert len(broken_ref_findings) == 1

    def test_file_hash_mismatch(self, tmp_path):
        """Modifying a content file should produce file_hash_mismatch."""
        _make_store_with_repo(tmp_path)

        content_file = tmp_path / "test__repo" / "test.py"
        content_file.write_text("# completely different content\n")

        result = lint_index("test/repo", storage_path=str(tmp_path))

        mismatch_findings = [
            f for f in result["findings"]
            if f["type"] == "file_hash_mismatch" and f["reason"] == "hash mismatch"
        ]
        assert len(mismatch_findings) == 1

    def test_file_hash_missing_content_file(self, tmp_path):
        """Deleting a content file should produce file_hash_mismatch with missing reason."""
        _make_store_with_repo(tmp_path)

        content_file = tmp_path / "test__repo" / "test.py"
        content_file.unlink()

        result = lint_index("test/repo", storage_path=str(tmp_path))

        missing_hash_findings = [
            f for f in result["findings"]
            if f["type"] == "file_hash_mismatch" and f["reason"] == "content file missing"
        ]
        assert len(missing_hash_findings) >= 1

    def test_trust_boundary(self, tmp_path):
        """Response must mark content as untrusted with boundary markers."""
        _make_store_with_repo(tmp_path)
        result = lint_index("test/repo", storage_path=str(tmp_path))

        assert result["_meta"]["contentTrust"] == "untrusted"
        assert "UNTRUSTED_CODE" in result["repo"]

    def test_missing_repo(self, tmp_path):
        """Nonexistent repo should return an error dict."""
        result = lint_index("nonexistent/repo", storage_path=str(tmp_path))
        assert "error" in result

    def test_summary_counts(self, tmp_path):
        """Summary should accurately count findings by type."""
        _make_store_with_repo(tmp_path)

        # Delete content file to create orphaned_symbol + file_hash_mismatch findings
        content_file = tmp_path / "test__repo" / "test.py"
        content_file.unlink()

        result = lint_index("test/repo", storage_path=str(tmp_path))

        assert result["summary"]["total_findings"] == len(result["findings"])
        by_type = result["summary"]["by_type"]
        # Verify each type count matches actual findings
        for finding_type, count in by_type.items():
            actual = len([f for f in result["findings"] if f["type"] == finding_type])
            assert count == actual, f"by_type[{finding_type}] = {count} but found {actual}"

    def test_ci_exit_key_registered(self):
        """lint_index ToolSpec should have ci_exit_key set to 'clean'."""
        specs = get_all_specs()
        assert specs["lint_index"].ci_exit_key == "clean"

    def test_ci_exit_code_on_findings(self, tmp_path):
        """CLI dispatch should exit 1 when lint_index finds issues."""
        import codesight_mcp.server as server_mod
        from codesight_mcp.server import _run_cli_tool

        store, index = _make_store_with_repo(tmp_path)

        content_file = tmp_path / "test__repo" / "test.py"
        content_file.unlink()

        old_path = server_mod._CODE_INDEX_PATH
        try:
            server_mod._CODE_INDEX_PATH = str(tmp_path)
            with pytest.raises(SystemExit) as exc_info:
                _run_cli_tool("lint_index", ["--repo", "test/repo"])
            assert exc_info.value.code == 1
        finally:
            server_mod._CODE_INDEX_PATH = old_path
