"""Tests for diff-aware (git-based) indexing in index_folder (Task 19)."""

from pathlib import Path
from unittest.mock import patch, MagicMock
import subprocess

import pytest

from codesight_mcp.tools.index_folder import (
    _is_git_repo,
    _git_head_commit,
    _git_changed_files,
    index_folder,
)
from codesight_mcp.storage.index_store import IndexStore


class TestIsGitRepo:
    def test_returns_true_for_git_repo(self, tmp_path):
        result = MagicMock()
        result.returncode = 0
        result.stdout = "true\n"
        with patch("codesight_mcp.tools.index_folder.subprocess.run", return_value=result) as mock_run:
            assert _is_git_repo(tmp_path) is True
            mock_run.assert_called_once()
            args = mock_run.call_args
            assert args[0][0] == ["git", "rev-parse", "--is-inside-work-tree"]
            assert args[1]["cwd"] == str(tmp_path)

    def test_returns_false_for_non_git_repo(self, tmp_path):
        result = MagicMock()
        result.returncode = 128
        result.stdout = ""
        with patch("codesight_mcp.tools.index_folder.subprocess.run", return_value=result):
            assert _is_git_repo(tmp_path) is False

    def test_returns_false_on_exception(self, tmp_path):
        with patch("codesight_mcp.tools.index_folder.subprocess.run", side_effect=FileNotFoundError):
            assert _is_git_repo(tmp_path) is False

    def test_returns_false_on_timeout(self, tmp_path):
        with patch("codesight_mcp.tools.index_folder.subprocess.run", side_effect=subprocess.TimeoutExpired("git", 5)):
            assert _is_git_repo(tmp_path) is False


class TestGitHeadCommit:
    def test_returns_commit_hash(self, tmp_path):
        result = MagicMock()
        result.returncode = 0
        result.stdout = "abc123def456\n"
        with patch("codesight_mcp.tools.index_folder.subprocess.run", return_value=result):
            assert _git_head_commit(tmp_path) == "abc123def456"

    def test_returns_none_on_failure(self, tmp_path):
        result = MagicMock()
        result.returncode = 128
        result.stdout = ""
        with patch("codesight_mcp.tools.index_folder.subprocess.run", return_value=result):
            assert _git_head_commit(tmp_path) is None

    def test_returns_none_on_exception(self, tmp_path):
        with patch("codesight_mcp.tools.index_folder.subprocess.run", side_effect=Exception("boom")):
            assert _git_head_commit(tmp_path) is None


class TestGitChangedFiles:
    def test_returns_changed_files(self, tmp_path):
        diff_result = MagicMock()
        diff_result.returncode = 0
        diff_result.stdout = "src/a.py\nsrc/b.py\n"

        ls_result = MagicMock()
        ls_result.returncode = 0
        ls_result.stdout = "src/c.py\n"

        with patch("codesight_mcp.tools.index_folder.subprocess.run", side_effect=[diff_result, ls_result]):
            changed = _git_changed_files(tmp_path, "abc123")
            assert changed == {"src/a.py", "src/b.py", "src/c.py"}

    def test_returns_none_on_diff_failure(self, tmp_path):
        result = MagicMock()
        result.returncode = 128
        result.stdout = ""
        with patch("codesight_mcp.tools.index_folder.subprocess.run", return_value=result):
            assert _git_changed_files(tmp_path, "abc123") is None

    def test_returns_none_on_exception(self, tmp_path):
        with patch("codesight_mcp.tools.index_folder.subprocess.run", side_effect=Exception("boom")):
            assert _git_changed_files(tmp_path, "abc123") is None

    def test_empty_diff_returns_empty_set(self, tmp_path):
        diff_result = MagicMock()
        diff_result.returncode = 0
        diff_result.stdout = ""

        ls_result = MagicMock()
        ls_result.returncode = 0
        ls_result.stdout = ""

        with patch("codesight_mcp.tools.index_folder.subprocess.run", side_effect=[diff_result, ls_result]):
            changed = _git_changed_files(tmp_path, "abc123")
            assert changed == set()


class TestDiffAwareIndexing:
    """Integration tests verifying diff-aware indexing behavior."""

    def test_full_index_stores_git_head(self, tmp_path):
        """First-time index in a git repo stores the commit hash."""
        py_file = tmp_path / "main.py"
        py_file.write_text("def hello():\n    return 'hi'\n")
        storage = tmp_path / "_storage"

        head_result = MagicMock(returncode=0, stdout="abc123def\n")
        git_check = MagicMock(returncode=0, stdout="true\n")

        def mock_run(cmd, **kwargs):
            if "rev-parse" in cmd and "--is-inside-work-tree" in cmd:
                return git_check
            if "rev-parse" in cmd and "HEAD" in cmd:
                return head_result
            raise ValueError(f"Unexpected command: {cmd}")

        with patch("codesight_mcp.tools.index_folder.subprocess.run", side_effect=mock_run):
            result = index_folder(
                path=str(tmp_path),
                use_ai_summaries=False,
                storage_path=str(storage),
                allowed_roots=[str(tmp_path)],
            )

        assert result["success"] is True

        # Verify git_head was stored
        store = IndexStore(base_path=str(storage))
        owner, name = result["repo"].split("/", 1)
        idx = store.load_index(owner, name)
        assert idx is not None
        assert idx.git_head == "abc123def"

    def test_non_git_folder_still_works(self, tmp_path):
        """Indexing a non-git folder works as before (no git_head stored)."""
        py_file = tmp_path / "main.py"
        py_file.write_text("def hello():\n    return 'hi'\n")
        storage = tmp_path / "_storage"

        git_check = MagicMock(returncode=128, stdout="")

        with patch("codesight_mcp.tools.index_folder.subprocess.run", return_value=git_check):
            result = index_folder(
                path=str(tmp_path),
                use_ai_summaries=False,
                storage_path=str(storage),
                allowed_roots=[str(tmp_path)],
            )

        assert result["success"] is True
        store = IndexStore(base_path=str(storage))
        owner, name = result["repo"].split("/", 1)
        idx = store.load_index(owner, name)
        assert idx is not None
        assert idx.git_head == ""

    def test_incremental_index_on_changed_files(self, tmp_path):
        """Re-indexing a git repo with changed files uses incremental path."""
        py_file = tmp_path / "main.py"
        py_file.write_text("def hello():\n    return 'hi'\n")
        other_file = tmp_path / "other.py"
        other_file.write_text("def other():\n    return 'other'\n")
        storage = tmp_path / "_storage"

        # First index: commit abc123
        git_check = MagicMock(returncode=0, stdout="true\n")
        head_result_1 = MagicMock(returncode=0, stdout="abc123\n")

        def mock_run_first(cmd, **kwargs):
            if "rev-parse" in cmd and "--is-inside-work-tree" in cmd:
                return git_check
            if "rev-parse" in cmd and "HEAD" in cmd:
                return head_result_1
            raise ValueError(f"Unexpected command: {cmd}")

        with patch("codesight_mcp.tools.index_folder.subprocess.run", side_effect=mock_run_first):
            result1 = index_folder(
                path=str(tmp_path),
                use_ai_summaries=False,
                storage_path=str(storage),
                allowed_roots=[str(tmp_path)],
            )
        assert result1["success"] is True
        assert result1["symbol_count"] >= 2

        # Modify one file
        py_file.write_text("def hello():\n    return 'hello world'\n")

        # Second index: commit def456, only main.py changed
        head_result_2 = MagicMock(returncode=0, stdout="def456\n")
        diff_result = MagicMock(returncode=0, stdout="main.py\n")
        ls_result = MagicMock(returncode=0, stdout="")

        def mock_run_second(cmd, **kwargs):
            if "rev-parse" in cmd and "--is-inside-work-tree" in cmd:
                return git_check
            if "rev-parse" in cmd and "HEAD" in cmd:
                return head_result_2
            if "diff" in cmd and "--name-only" in cmd:
                return diff_result
            if "ls-files" in cmd:
                return ls_result
            raise ValueError(f"Unexpected command: {cmd}")

        with patch("codesight_mcp.tools.index_folder.subprocess.run", side_effect=mock_run_second):
            result2 = index_folder(
                path=str(tmp_path),
                use_ai_summaries=False,
                storage_path=str(storage),
                allowed_roots=[str(tmp_path)],
            )

        assert result2["success"] is True
        assert result2.get("incremental") is True
        assert result2["changed_files"] == 1
        assert result2["new_files"] == 0
        assert result2["deleted_files"] == 0

        # Verify the index was updated with new git_head
        store = IndexStore(base_path=str(storage))
        owner, name = result2["repo"].split("/", 1)
        idx = store.load_index(owner, name)
        assert idx.git_head == "def456"
        # Both files should still be in the index
        assert len(idx.source_files) == 2

    def test_fallback_to_full_index_on_git_error(self, tmp_path):
        """If git diff fails, falls back to full re-index."""
        py_file = tmp_path / "main.py"
        py_file.write_text("def hello():\n    return 'hi'\n")
        storage = tmp_path / "_storage"

        # First index with git_head
        git_check = MagicMock(returncode=0, stdout="true\n")
        head_result = MagicMock(returncode=0, stdout="abc123\n")

        call_count = [0]

        def mock_run_first(cmd, **kwargs):
            if "rev-parse" in cmd and "--is-inside-work-tree" in cmd:
                return git_check
            if "rev-parse" in cmd and "HEAD" in cmd:
                return head_result
            raise ValueError(f"Unexpected command: {cmd}")

        with patch("codesight_mcp.tools.index_folder.subprocess.run", side_effect=mock_run_first):
            result1 = index_folder(
                path=str(tmp_path),
                use_ai_summaries=False,
                storage_path=str(storage),
                allowed_roots=[str(tmp_path)],
            )
        assert result1["success"] is True

        # Second index: git diff fails
        head_result_2 = MagicMock(returncode=0, stdout="def456\n")
        diff_fail = MagicMock(returncode=128, stdout="")

        def mock_run_second(cmd, **kwargs):
            if "rev-parse" in cmd and "--is-inside-work-tree" in cmd:
                return git_check
            if "rev-parse" in cmd and "HEAD" in cmd:
                return head_result_2
            if "diff" in cmd:
                return diff_fail
            raise ValueError(f"Unexpected command: {cmd}")

        with patch("codesight_mcp.tools.index_folder.subprocess.run", side_effect=mock_run_second):
            result2 = index_folder(
                path=str(tmp_path),
                use_ai_summaries=False,
                storage_path=str(storage),
                allowed_roots=[str(tmp_path)],
            )

        assert result2["success"] is True
        # Should NOT have incremental flag since it fell back to full
        assert "incremental" not in result2

    def test_same_commit_does_full_reindex(self, tmp_path):
        """If HEAD hasn't changed, skip diff-aware and do full re-index."""
        py_file = tmp_path / "main.py"
        py_file.write_text("def hello():\n    return 'hi'\n")
        storage = tmp_path / "_storage"

        git_check = MagicMock(returncode=0, stdout="true\n")
        head_result = MagicMock(returncode=0, stdout="abc123\n")

        def mock_run(cmd, **kwargs):
            if "rev-parse" in cmd and "--is-inside-work-tree" in cmd:
                return git_check
            if "rev-parse" in cmd and "HEAD" in cmd:
                return head_result
            raise ValueError(f"Unexpected command: {cmd}")

        with patch("codesight_mcp.tools.index_folder.subprocess.run", side_effect=mock_run):
            result1 = index_folder(
                path=str(tmp_path),
                use_ai_summaries=False,
                storage_path=str(storage),
                allowed_roots=[str(tmp_path)],
            )
        assert result1["success"] is True

        # Re-index with same HEAD — should do full re-index (no incremental)
        with patch("codesight_mcp.tools.index_folder.subprocess.run", side_effect=mock_run):
            result2 = index_folder(
                path=str(tmp_path),
                use_ai_summaries=False,
                storage_path=str(storage),
                allowed_roots=[str(tmp_path)],
            )
        assert result2["success"] is True
        assert "incremental" not in result2
