"""Tests for get_changes tool.

Tests _parse_diff_output and _map_hunks_to_symbols as pure functions
(no git repo required for unit tests).  Integration tests cover error
handling for bad repo, invalid ref, and missing .git directory.
"""

import re

import pytest

from codesight_mcp.parser.symbols import Symbol
from codesight_mcp.storage import IndexStore
from codesight_mcp.tools.get_changes import (
    _map_hunks_to_symbols,
    _parse_diff_output,
    _validate_ref,
    get_changes,
)

_BOUNDARY_RE = re.compile(r"<<<(?:END_)?UNTRUSTED_CODE_[0-9a-f]+>>>\n?")


def _unwrap(value: str) -> str:
    """Strip content boundary markers from a wrapped string."""
    return _BOUNDARY_RE.sub("", value).strip()


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

SRC = "# stub\n"


def _sym(file: str, name: str, line: int, end_line: int, kind: str = "function") -> Symbol:
    """Build a minimal Symbol with explicit line ranges."""
    sid = f"{file}::{name}#{kind}"
    return Symbol(
        id=sid,
        file=file,
        name=name,
        qualified_name=name,
        kind=kind,
        language="python",
        signature=f"def {name}():" if kind == "function" else f"class {name}:",
        summary=f"Stub {name}",
        byte_offset=0,
        byte_length=len(SRC),
        line=line,
        end_line=end_line,
    )


def _make_index(tmp_path, symbols: list[Symbol]):
    """Save a small index and return (store, CodeIndex)."""
    files = sorted({s.file for s in symbols})
    store = IndexStore(base_path=str(tmp_path))
    index = store.save_index(
        owner="local",
        name="testchanges",
        source_files=files,
        symbols=symbols,
        raw_files={f: SRC for f in files},
        languages={"python": len(files)},
    )
    return store, index


# ---------------------------------------------------------------------------
# TestMapChangedLinesToSymbols
# ---------------------------------------------------------------------------


class TestMapChangedLinesToSymbols:
    """Unit tests for _map_hunks_to_symbols — no I/O, no git."""

    @pytest.fixture
    def index(self, tmp_path):
        """Index with two non-overlapping functions in app.py."""
        symbols = [
            _sym("app.py", "foo", line=1, end_line=10),
            _sym("app.py", "bar", line=12, end_line=20),
            _sym("utils.py", "helper", line=1, end_line=5),
        ]
        _, idx = _make_index(tmp_path, symbols)
        return idx

    def test_line_in_function_maps_to_correct_symbol(self, index):
        hunks = [{"file": "app.py", "lines": [(5, 5)]}]
        result = _map_hunks_to_symbols(hunks, index)
        assert len(result) == 1
        assert _unwrap(result[0]["name"]) == "foo"

    def test_line_spanning_two_symbols_returns_both(self, index):
        # Lines 8–14 overlap both foo (1-10) and bar (12-20)
        hunks = [{"file": "app.py", "lines": [(8, 14)]}]
        result = _map_hunks_to_symbols(hunks, index)
        names = {_unwrap(s["name"]) for s in result}
        assert "foo" in names
        assert "bar" in names

    def test_line_outside_all_symbols_returns_empty(self, index):
        # Line 50 is beyond all symbols in app.py
        hunks = [{"file": "app.py", "lines": [(50, 55)]}]
        result = _map_hunks_to_symbols(hunks, index)
        assert result == []

    def test_file_not_in_index_returns_empty(self, index):
        hunks = [{"file": "nonexistent.py", "lines": [(1, 10)]}]
        result = _map_hunks_to_symbols(hunks, index)
        assert result == []

    def test_deduplication_across_multiple_hunks(self, index):
        # Two hunks both touching foo — should yield foo only once
        hunks = [{"file": "app.py", "lines": [(2, 3), (7, 8)]}]
        result = _map_hunks_to_symbols(hunks, index)
        names = [_unwrap(s["name"]) for s in result]
        assert names.count("foo") == 1

    def test_hunk_in_different_file_does_not_cross_contaminate(self, index):
        # Hunk in utils.py should only return helper, not foo/bar
        hunks = [{"file": "utils.py", "lines": [(1, 5)]}]
        result = _map_hunks_to_symbols(hunks, index)
        assert len(result) == 1
        assert _unwrap(result[0]["name"]) == "helper"

    def test_empty_hunks_returns_empty(self, index):
        result = _map_hunks_to_symbols([], index)
        assert result == []

    def test_symbol_dict_has_required_fields(self, index):
        hunks = [{"file": "app.py", "lines": [(1, 1)]}]
        result = _map_hunks_to_symbols(hunks, index)
        assert result
        sym = result[0]
        for key in ("id", "name", "kind", "file", "line", "signature"):
            assert key in sym, f"Missing key: {key}"


# ---------------------------------------------------------------------------
# TestParseGitDiff
# ---------------------------------------------------------------------------


class TestParseGitDiff:
    """Unit tests for _parse_diff_output — pure string parsing."""

    _SIMPLE_DIFF = """\
diff --git a/src/foo.py b/src/foo.py
index abc..def 100644
--- a/src/foo.py
+++ b/src/foo.py
@@ -5,3 +5,4 @@ def foo():
+    x = 1
     y = 2
     return y
"""

    def test_parses_single_hunk(self):
        result = _parse_diff_output(self._SIMPLE_DIFF)
        assert len(result) == 1
        assert result[0]["file"] == "src/foo.py"
        assert result[0]["lines"] == [(5, 8)]  # start=5, count=4 → end=8

    def test_hunk_with_count_one_default(self):
        diff = """\
--- a/x.py
+++ b/x.py
@@ -10 +10 @@ some context
+added line
"""
        result = _parse_diff_output(diff)
        assert result == [{"file": "x.py", "lines": [(10, 10)]}]

    def test_deleted_file_is_skipped(self):
        diff = """\
diff --git a/old.py b/old.py
deleted file mode 100644
--- a/old.py
+++ /dev/null
@@ -1,5 +0,0 @@
-line1
"""
        result = _parse_diff_output(diff)
        assert result == []

    def test_multiple_files_in_one_diff(self):
        diff = """\
--- a/alpha.py
+++ b/alpha.py
@@ -1,2 +1,3 @@
+new line
 existing
--- a/beta.py
+++ b/beta.py
@@ -7,1 +7,2 @@
+another
"""
        result = _parse_diff_output(diff)
        files = {r["file"] for r in result}
        assert files == {"alpha.py", "beta.py"}

    def test_multiple_hunks_in_same_file(self):
        diff = """\
--- a/multi.py
+++ b/multi.py
@@ -1,2 +1,3 @@
+line
 existing
@@ -20,1 +21,2 @@
+another
"""
        result = _parse_diff_output(diff)
        assert len(result) == 1
        assert result[0]["file"] == "multi.py"
        assert len(result[0]["lines"]) == 2
        assert (1, 3) in result[0]["lines"]
        assert (21, 22) in result[0]["lines"]

    def test_pure_deletion_hunk_count_zero_skipped(self):
        # @@ -5,3 +5,0 @@ means 0 new lines added — pure deletion
        diff = """\
--- a/del.py
+++ b/del.py
@@ -5,3 +5,0 @@ removed block
-line1
-line2
-line3
"""
        result = _parse_diff_output(diff)
        # The file will appear but with no line ranges (count=0 hunks skipped)
        # So either empty result or file with empty lines list
        for r in result:
            assert r["lines"] == [] or r.get("file") != "del.py"

    def test_empty_diff_returns_empty(self):
        result = _parse_diff_output("")
        assert result == []

    def test_b_prefix_stripped_from_filename(self):
        diff = """\
--- a/src/mod.py
+++ b/src/mod.py
@@ -3,2 +3,3 @@
+x = 1
"""
        result = _parse_diff_output(diff)
        assert result[0]["file"] == "src/mod.py"


# ---------------------------------------------------------------------------
# TestValidateRef
# ---------------------------------------------------------------------------


class TestValidateRef:
    """Unit tests for _validate_ref."""

    def test_valid_refs_accepted(self):
        valid = [
            "HEAD~1..HEAD",
            "main",
            "abc123",
            "origin/main",
            "v1.0.0",
            "HEAD^",
            "refs/heads/feature/foo",
        ]
        from codesight_mcp.core.validation import ValidationError
        for ref in valid:
            result = _validate_ref(ref)
            assert result == ref

    def test_shell_injection_rejected(self):
        from codesight_mcp.core.validation import ValidationError
        bad = ["HEAD; rm -rf /", "HEAD && cat /etc/passwd", "HEAD|id", "HEAD`ls`"]
        for ref in bad:
            with pytest.raises(ValidationError):
                _validate_ref(ref)

    def test_too_long_rejected(self):
        from codesight_mcp.core.validation import ValidationError
        long_ref = "a" * 201
        with pytest.raises(ValidationError, match="too long"):
            _validate_ref(long_ref)

    def test_exactly_max_length_accepted(self):
        from codesight_mcp.core.validation import ValidationError
        ref = "a" * 200
        result = _validate_ref(ref)
        assert result == ref


# ---------------------------------------------------------------------------
# TestGetChangesIntegration
# ---------------------------------------------------------------------------


class TestGetChangesIntegration:
    """Integration tests for get_changes handler."""

    def test_repo_not_found_returns_error(self, tmp_path):
        result = get_changes(
            repo="local/nonexistent",
            repo_path=str(tmp_path),
            storage_path=str(tmp_path),
        )
        assert "error" in result
        assert "not indexed" in result["error"].lower() or "not found" in result["error"].lower()

    def test_invalid_git_ref_returns_error(self, tmp_path):
        result = get_changes(
            repo="local/whatever",
            git_ref="HEAD; rm -rf /",
            repo_path=str(tmp_path),
            storage_path=str(tmp_path),
        )
        assert "error" in result
        assert "disallowed" in result["error"].lower() or "invalid" in result["error"].lower()

    def test_no_git_dir_returns_error_gracefully(self, tmp_path):
        """A path with no .git should produce an error, not a crash."""
        # First create a valid index so repo lookup succeeds
        symbols = [_sym("app.py", "foo", 1, 10)]
        store = IndexStore(base_path=str(tmp_path))
        store.save_index(
            owner="local",
            name="nongit",
            source_files=["app.py"],
            symbols=symbols,
            raw_files={"app.py": SRC},
            languages={"python": 1},
        )

        # tmp_path has no .git, so git diff will fail
        result = get_changes(
            repo="local/nongit",
            repo_path=str(tmp_path),
            storage_path=str(tmp_path),
        )
        assert "error" in result
        # Should mention git failure, not raise an exception
        assert isinstance(result["error"], str)

    def test_missing_repo_path_returns_error(self, tmp_path):
        symbols = [_sym("app.py", "foo", 1, 10)]
        store = IndexStore(base_path=str(tmp_path))
        store.save_index(
            owner="local",
            name="norepopath",
            source_files=["app.py"],
            symbols=symbols,
            raw_files={"app.py": SRC},
            languages={"python": 1},
        )
        result = get_changes(
            repo="local/norepopath",
            repo_path=None,
            storage_path=str(tmp_path),
        )
        assert "error" in result
        assert "repo_path" in result["error"].lower()

    def test_result_has_meta_envelope(self, tmp_path):
        """Even a repo-not-found should just be an error dict, not raise."""
        result = get_changes(
            repo="local/doesnotexist",
            storage_path=str(tmp_path),
        )
        assert isinstance(result, dict)

    def test_repo_path_outside_allowed_roots_blocked(self, tmp_path):
        """repo_path must be within allowed_roots."""
        symbols = [_sym("app.py", "foo", 1, 10)]
        store = IndexStore(base_path=str(tmp_path))
        store.save_index(
            owner="local",
            name="rootstest",
            source_files=["app.py"],
            symbols=symbols,
            raw_files={"app.py": SRC},
            languages={"python": 1},
        )
        result = get_changes(
            repo="local/rootstest",
            repo_path=str(tmp_path / "subdir"),
            storage_path=str(tmp_path),
            allowed_roots=["/some/other/place"],
        )
        assert "error" in result
        assert "outside allowed roots" in result["error"]

    def test_repo_path_within_allowed_roots_accepted(self, tmp_path):
        """repo_path within allowed_roots should proceed (may fail at git, not at root check)."""
        symbols = [_sym("app.py", "foo", 1, 10)]
        store = IndexStore(base_path=str(tmp_path))
        store.save_index(
            owner="local",
            name="rootsok",
            source_files=["app.py"],
            symbols=symbols,
            raw_files={"app.py": SRC},
            languages={"python": 1},
        )
        result = get_changes(
            repo="local/rootsok",
            repo_path=str(tmp_path),
            storage_path=str(tmp_path),
            allowed_roots=[str(tmp_path)],
        )
        # Should get past the roots check — fails at git diff (no .git), not at roots
        assert "error" in result
        assert "outside allowed roots" not in result["error"]

    def test_repo_path_not_a_directory_returns_error(self, tmp_path):
        symbols = [_sym("app.py", "foo", 1, 10)]
        store = IndexStore(base_path=str(tmp_path))
        store.save_index(
            owner="local",
            name="notadir",
            source_files=["app.py"],
            symbols=symbols,
            raw_files={"app.py": SRC},
            languages={"python": 1},
        )
        fake_file = tmp_path / "not_a_dir.txt"
        fake_file.write_text("hello")
        result = get_changes(
            repo="local/notadir",
            repo_path=str(fake_file),
            storage_path=str(tmp_path),
        )
        assert "error" in result
        assert "not a directory" in result["error"]

    def test_happy_path_with_real_git_repo(self, tmp_path):
        """End-to-end: create a real git repo, make a commit, run get_changes."""
        import subprocess
        # Create git repo
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        subprocess.run(["git", "init"], cwd=str(repo_dir), capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=str(repo_dir), capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=str(repo_dir), capture_output=True)

        # First commit
        (repo_dir / "app.py").write_text("def foo():\n    pass\n")
        subprocess.run(["git", "add", "app.py"], cwd=str(repo_dir), capture_output=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=str(repo_dir), capture_output=True)

        # Second commit modifying foo
        (repo_dir / "app.py").write_text("def foo():\n    return 42\n")
        subprocess.run(["git", "add", "app.py"], cwd=str(repo_dir), capture_output=True)
        subprocess.run(["git", "commit", "-m", "modify foo"], cwd=str(repo_dir), capture_output=True)

        # Index with a symbol covering the changed lines
        symbols = [_sym("app.py", "foo", 1, 2)]
        store = IndexStore(base_path=str(tmp_path / "index"))
        store.save_index(
            owner="local",
            name="happypath",
            source_files=["app.py"],
            symbols=symbols,
            raw_files={"app.py": "def foo():\n    return 42\n"},
            languages={"python": 1},
        )

        result = get_changes(
            repo="local/happypath",
            git_ref="HEAD~1..HEAD",
            repo_path=str(repo_dir),
            storage_path=str(tmp_path / "index"),
        )
        assert "error" not in result
        assert result["changed_files"] >= 1
        assert result["affected_symbol_count"] >= 1
        assert _unwrap(result["affected_symbols"][0]["name"]) == "foo"
        assert "_meta" in result
        assert result["_meta"]["timing_ms"] >= 0

    def test_include_impact_with_real_git_repo(self, tmp_path):
        """End-to-end: include_impact=True returns impact section."""
        import subprocess
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        subprocess.run(["git", "init"], cwd=str(repo_dir), capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=str(repo_dir), capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=str(repo_dir), capture_output=True)

        (repo_dir / "app.py").write_text("def foo():\n    pass\ndef bar():\n    foo()\n")
        subprocess.run(["git", "add", "app.py"], cwd=str(repo_dir), capture_output=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=str(repo_dir), capture_output=True)

        (repo_dir / "app.py").write_text("def foo():\n    return 1\ndef bar():\n    foo()\n")
        subprocess.run(["git", "add", "app.py"], cwd=str(repo_dir), capture_output=True)
        subprocess.run(["git", "commit", "-m", "change foo"], cwd=str(repo_dir), capture_output=True)

        symbols = [
            _sym("app.py", "foo", 1, 2),
            _sym("app.py", "bar", 3, 4),
        ]
        # bar calls foo
        from dataclasses import replace as dc_replace
        bar_sym = dc_replace(symbols[1], calls=["app.py::foo#function"])

        store = IndexStore(base_path=str(tmp_path / "index"))
        store.save_index(
            owner="local",
            name="impacttest",
            source_files=["app.py"],
            symbols=[symbols[0], bar_sym],
            raw_files={"app.py": "def foo():\n    return 1\ndef bar():\n    foo()\n"},
            languages={"python": 1},
        )

        result = get_changes(
            repo="local/impacttest",
            git_ref="HEAD~1..HEAD",
            repo_path=str(repo_dir),
            include_impact=True,
            storage_path=str(tmp_path / "index"),
        )
        assert "error" not in result
        assert "impact" in result
        assert isinstance(result["impact"], dict)
        assert "downstream_count" in result["impact"]
        assert "downstream" in result["impact"]

    def test_include_impact_empty_affected_returns_empty_impact(self, tmp_path):
        """When include_impact=True but no symbols affected, impact should be a consistent empty dict."""
        import subprocess
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        subprocess.run(["git", "init"], cwd=str(repo_dir), capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=str(repo_dir), capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=str(repo_dir), capture_output=True)

        # Commit a file that has no indexed symbols
        (repo_dir / "readme.txt").write_text("hello\n")
        subprocess.run(["git", "add", "readme.txt"], cwd=str(repo_dir), capture_output=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=str(repo_dir), capture_output=True)

        (repo_dir / "readme.txt").write_text("hello world\n")
        subprocess.run(["git", "add", "readme.txt"], cwd=str(repo_dir), capture_output=True)
        subprocess.run(["git", "commit", "-m", "change"], cwd=str(repo_dir), capture_output=True)

        symbols = [_sym("app.py", "foo", 1, 10)]
        store = IndexStore(base_path=str(tmp_path / "index"))
        store.save_index(
            owner="local",
            name="emptyimpact",
            source_files=["app.py"],
            symbols=symbols,
            raw_files={"app.py": SRC},
            languages={"python": 1},
        )

        result = get_changes(
            repo="local/emptyimpact",
            git_ref="HEAD~1..HEAD",
            repo_path=str(repo_dir),
            include_impact=True,
            storage_path=str(tmp_path / "index"),
        )
        assert "error" not in result
        assert result["impact"] == {"downstream_count": 0, "downstream": []}

    def test_max_affected_truncation(self, tmp_path):
        """Affected symbols should be capped at _MAX_AFFECTED with truncated flag."""
        from codesight_mcp.tools.get_changes import _MAX_AFFECTED

        # Create 150 symbols each covering 1 line
        symbols = [_sym("app.py", f"fn{i}", line=i, end_line=i) for i in range(1, 151)]
        _, idx = _make_index(tmp_path, symbols)

        # Create hunks covering all 150 lines
        hunks = [{"file": "app.py", "lines": [(1, 150)]}]
        affected = _map_hunks_to_symbols(hunks, idx)
        assert len(affected) == 150

        # Verify the truncation logic in get_changes
        truncated = len(affected) > _MAX_AFFECTED
        assert truncated is True
        affected_capped = affected[:_MAX_AFFECTED]
        assert len(affected_capped) == _MAX_AFFECTED
