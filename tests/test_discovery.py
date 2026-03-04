"""Tests for the discovery module — local file walks and GitHub tree filtering."""

import os
import tempfile
from pathlib import Path

import pytest

from ironmunch.discovery import (
    SKIP_PATTERNS,
    should_skip_file,
    _load_gitignore,
    _is_symlink_escape,
    _priority_key,
    discover_local_files,
    parse_github_url,
    discover_source_files,
)
from ironmunch.core.limits import MAX_FILE_SIZE, MAX_FILE_COUNT


# ---------------------------------------------------------------------------
# parse_github_url
# ---------------------------------------------------------------------------

class TestParseGithubUrl:
    def test_https_url(self):
        owner, repo = parse_github_url("https://github.com/octocat/Hello-World")
        assert owner == "octocat"
        assert repo == "Hello-World"

    def test_https_url_with_git_suffix(self):
        owner, repo = parse_github_url("https://github.com/octocat/Hello-World.git")
        assert owner == "octocat"
        assert repo == "Hello-World"

    def test_owner_repo_shorthand(self):
        owner, repo = parse_github_url("octocat/Hello-World")
        assert owner == "octocat"
        assert repo == "Hello-World"

    def test_owner_repo_with_git_suffix(self):
        owner, repo = parse_github_url("octocat/Hello-World.git")
        assert owner == "octocat"
        assert repo == "Hello-World"

    def test_url_with_trailing_path(self):
        owner, repo = parse_github_url("https://github.com/octocat/Hello-World/tree/main")
        assert owner == "octocat"
        assert repo == "Hello-World"

    def test_invalid_url_raises(self):
        with pytest.raises(ValueError, match="Could not parse"):
            parse_github_url("https://github.com/")

    def test_single_segment_raises(self):
        with pytest.raises(ValueError, match="Could not parse"):
            parse_github_url("just-a-name")


# ---------------------------------------------------------------------------
# should_skip_file
# ---------------------------------------------------------------------------

class TestShouldSkipFile:
    def test_node_modules(self):
        assert should_skip_file("node_modules/lodash/index.js")

    def test_pycache(self):
        assert should_skip_file("src/__pycache__/module.cpython-311.pyc")

    def test_git_directory(self):
        assert should_skip_file(".git/objects/pack/something")

    def test_minified_js(self):
        assert should_skip_file("vendor/lib.min.js")

    def test_package_lock(self):
        assert should_skip_file("package-lock.json")

    def test_yarn_lock(self):
        assert should_skip_file("yarn.lock")

    def test_normal_source_file(self):
        assert not should_skip_file("src/main.py")

    def test_nested_source_file(self):
        assert not should_skip_file("src/utils/helpers.ts")

    def test_backslash_normalization(self):
        assert should_skip_file("node_modules\\lodash\\index.js")

    def test_build_directory(self):
        assert should_skip_file("build/output/bundle.js")

    def test_venv(self):
        assert should_skip_file(".venv/lib/python3.11/site-packages/foo.py")

    def test_generated_directory(self):
        assert should_skip_file("generated/api_pb2.py")

    def test_migrations(self):
        assert should_skip_file("migrations/0001_initial.py")


# ---------------------------------------------------------------------------
# _load_gitignore
# ---------------------------------------------------------------------------

class TestLoadGitignore:
    def test_loads_gitignore(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / ".gitignore").write_text("*.log\nbuild/\n")
            spec = _load_gitignore(root)
            assert spec is not None
            assert spec.match_file("error.log")
            assert spec.match_file("build/output.js")
            assert not spec.match_file("src/main.py")

    def test_returns_none_when_missing(self):
        with tempfile.TemporaryDirectory() as d:
            assert _load_gitignore(Path(d)) is None


# ---------------------------------------------------------------------------
# _is_symlink_escape
# ---------------------------------------------------------------------------

class TestIsSymlinkEscape:
    def test_symlink_inside_root(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            target = root / "real.py"
            target.write_text("x = 1")
            link = root / "link.py"
            link.symlink_to(target)
            assert not _is_symlink_escape(root, link)

    def test_symlink_outside_root(self):
        with tempfile.TemporaryDirectory() as outer:
            outside = Path(outer) / "outside.py"
            outside.write_text("x = 1")
            with tempfile.TemporaryDirectory() as inner:
                root = Path(inner)
                link = root / "escape.py"
                link.symlink_to(outside)
                assert _is_symlink_escape(root, link)


# ---------------------------------------------------------------------------
# _priority_key
# ---------------------------------------------------------------------------

class TestPriorityKey:
    def test_src_first(self):
        assert _priority_key("src/main.py") < _priority_key("other/main.py")

    def test_lib_before_non_priority(self):
        assert _priority_key("lib/util.py") < _priority_key("app/util.py")

    def test_shallower_preferred(self):
        assert _priority_key("src/main.py") < _priority_key("src/deep/nested/main.py")


# ---------------------------------------------------------------------------
# discover_local_files
# ---------------------------------------------------------------------------

class TestDiscoverLocalFiles:
    def _make_tree(self, root: Path, files: dict[str, str]) -> None:
        """Create a file tree under root. Keys are relative paths, values are content."""
        for rel_path, content in files.items():
            fp = root / rel_path
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(content, encoding="utf-8")

    def _rel_paths(self, root: Path, files: list[Path]) -> set[str]:
        """Get relative posix paths from discovered files.

        Uses resolved root to handle macOS /tmp -> /private/tmp symlink.
        """
        resolved = root.resolve()
        return {f.relative_to(resolved).as_posix() for f in files}

    def test_discovers_python_files(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._make_tree(root, {
                "src/main.py": "print('hello')",
                "src/util.py": "x = 1",
            })
            files, warnings = discover_local_files(root)
            rel_paths = self._rel_paths(root, files)
            assert "src/main.py" in rel_paths
            assert "src/util.py" in rel_paths

    def test_skips_non_language_files(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._make_tree(root, {
                "src/main.py": "x = 1",
                "readme.txt": "hello",
                "data.csv": "a,b,c",
            })
            files, _ = discover_local_files(root)
            rel_paths = self._rel_paths(root, files)
            assert "src/main.py" in rel_paths
            assert "readme.txt" not in rel_paths
            assert "data.csv" not in rel_paths

    def test_respects_gitignore(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._make_tree(root, {
                ".gitignore": "ignored/\n",
                "src/main.py": "x = 1",
                "ignored/secret.py": "password = 'oops'",
            })
            files, _ = discover_local_files(root)
            rel_paths = self._rel_paths(root, files)
            assert "src/main.py" in rel_paths
            assert "ignored/secret.py" not in rel_paths

    def test_respects_extra_ignore_patterns(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._make_tree(root, {
                "src/main.py": "x = 1",
                "src/generated.py": "auto = True",
            })
            files, _ = discover_local_files(root, extra_ignore_patterns=["generated.py"])
            rel_paths = self._rel_paths(root, files)
            assert "src/main.py" in rel_paths
            assert "src/generated.py" not in rel_paths

    def test_skips_secret_files(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            # .env would match secret pattern; use a known extension to pass lang filter
            self._make_tree(root, {
                "src/main.py": "x = 1",
                "src/credentials.json": '{"key": "val"}',
            })
            files, warnings = discover_local_files(root)
            rel_paths = self._rel_paths(root, files)
            assert "src/main.py" in rel_paths
            # credentials.json is a secret file AND not a supported lang ext
            assert "src/credentials.json" not in rel_paths

    def test_secret_file_warning(self):
        """Secret .py files should be warned about."""
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            # Create a file whose name matches secret patterns AND has .py extension
            # secret* pattern matches filenames starting with "secret"
            self._make_tree(root, {
                "src/main.py": "x = 1",
            })
            # Create a file named like a secret but with .py extension
            secret_py = root / "src" / "secret.py"
            secret_py.write_text("API_KEY = 'abc'")
            # is_secret_file matches on the filename; "secret.py" matches "secret*"
            # secret check runs BEFORE extension filter in the pipeline
            files, warnings = discover_local_files(root)
            # secret.py matches "secret*" pattern, should be skipped with warning
            rel_paths = self._rel_paths(root, files)
            assert "src/secret.py" not in rel_paths
            assert any("secret" in w for w in warnings)

    def test_skips_node_modules(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._make_tree(root, {
                "src/main.py": "x = 1",
                "node_modules/lodash/index.js": "module.exports = {}",
            })
            files, _ = discover_local_files(root)
            rel_paths = self._rel_paths(root, files)
            assert "node_modules/lodash/index.js" not in rel_paths

    def test_max_files_limit(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            # Create more files than the limit
            tree = {}
            for i in range(10):
                tree[f"src/file_{i:03d}.py"] = f"x = {i}"
            self._make_tree(root, tree)
            files, _ = discover_local_files(root, max_files=5)
            assert len(files) == 5

    def test_max_size_limit(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._make_tree(root, {
                "small.py": "x = 1",
            })
            # Create an oversized file
            big_file = root / "big.py"
            big_file.write_text("x" * (MAX_FILE_SIZE + 1))
            files, _ = discover_local_files(root)
            rel_paths = self._rel_paths(root, files)
            assert "small.py" in rel_paths
            assert "big.py" not in rel_paths

    def test_skips_symlinks_by_default(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._make_tree(root, {"real.py": "x = 1"})
            link = root / "linked.py"
            link.symlink_to(root / "real.py")
            files, _ = discover_local_files(root)
            rel_paths = self._rel_paths(root, files)
            assert "real.py" in rel_paths
            assert "linked.py" not in rel_paths

    def test_follows_symlinks_when_enabled(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._make_tree(root, {"real.py": "x = 1"})
            link = root / "linked.py"
            link.symlink_to(root / "real.py")
            files, _ = discover_local_files(root, follow_symlinks=True)
            rel_paths = self._rel_paths(root, files)
            assert "real.py" in rel_paths
            assert "linked.py" in rel_paths

    def test_binary_content_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._make_tree(root, {"good.py": "x = 1"})
            # Write a .py file with null bytes (binary content)
            binary_py = root / "binary.py"
            binary_py.write_bytes(b"x = 1\x00\x00\x00")
            files, warnings = discover_local_files(root)
            rel_paths = self._rel_paths(root, files)
            assert "good.py" in rel_paths
            assert "binary.py" not in rel_paths
            assert any("binary content" in w for w in warnings)

    def test_priority_sorting_when_truncated(self):
        """When max_files truncates, src/ files should be preferred."""
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            tree = {
                "src/core.py": "x = 1",
                "src/util.py": "y = 2",
                "other/a.py": "a = 1",
                "other/b.py": "b = 1",
                "other/c.py": "c = 1",
            }
            self._make_tree(root, tree)
            files, _ = discover_local_files(root, max_files=2)
            rel_paths = self._rel_paths(root, files)
            # src/ files should be prioritized
            assert "src/core.py" in rel_paths or "src/util.py" in rel_paths

    def test_empty_directory_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            files, warnings = discover_local_files(Path(d))
            assert files == []
            assert warnings == []

    def test_discovers_multiple_languages(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._make_tree(root, {
                "src/main.py": "x = 1",
                "src/app.js": "const x = 1;",
                "src/util.ts": "let y: number = 2;",
                "src/lib.go": "package main",
                "src/mod.rs": "fn main() {}",
            })
            files, _ = discover_local_files(root)
            extensions = {f.suffix for f in files}
            assert ".py" in extensions
            assert ".js" in extensions
            assert ".ts" in extensions
            assert ".go" in extensions
            assert ".rs" in extensions


# ---------------------------------------------------------------------------
# discover_source_files (GitHub tree filtering)
# ---------------------------------------------------------------------------

class TestDiscoverSourceFiles:
    def _make_entries(self, paths: list[tuple[str, int]]) -> list[dict]:
        """Create tree entry dicts from (path, size) tuples."""
        return [
            {"path": p, "type": "blob", "size": s}
            for p, s in paths
        ]

    def test_filters_by_extension(self):
        entries = self._make_entries([
            ("src/main.py", 100),
            ("readme.md", 200),
            ("data.csv", 300),
        ])
        result = discover_source_files(entries)
        assert result == ["src/main.py"]

    def test_filters_non_blobs(self):
        entries = [
            {"path": "src", "type": "tree", "size": 0},
            {"path": "src/main.py", "type": "blob", "size": 100},
        ]
        result = discover_source_files(entries)
        assert result == ["src/main.py"]

    def test_filters_skip_patterns(self):
        entries = self._make_entries([
            ("src/main.py", 100),
            ("node_modules/lodash/index.js", 500),
            ("build/output.js", 200),
        ])
        result = discover_source_files(entries)
        assert result == ["src/main.py"]

    def test_filters_secrets(self):
        entries = self._make_entries([
            ("src/main.py", 100),
            ("src/.env", 50),
            ("src/credentials.json", 100),
        ])
        result = discover_source_files(entries)
        assert result == ["src/main.py"]

    def test_filters_oversized(self):
        entries = self._make_entries([
            ("src/main.py", 100),
            ("src/huge.py", MAX_FILE_SIZE + 1),
        ])
        result = discover_source_files(entries)
        assert result == ["src/main.py"]

    def test_respects_gitignore_content(self):
        entries = self._make_entries([
            ("src/main.py", 100),
            ("src/ignored.py", 100),
        ])
        result = discover_source_files(entries, gitignore_content="ignored.py\n")
        assert result == ["src/main.py"]

    def test_max_files_with_priority(self):
        entries = self._make_entries([
            ("other/a.py", 100),
            ("other/b.py", 100),
            ("other/c.py", 100),
            ("src/core.py", 100),
            ("src/util.py", 100),
            ("lib/helper.py", 100),
        ])
        result = discover_source_files(entries, max_files=3)
        assert len(result) == 3
        # src/ and lib/ should be prioritized
        assert "src/core.py" in result
        assert "src/util.py" in result
        assert "lib/helper.py" in result

    def test_empty_entries(self):
        assert discover_source_files([]) == []

    def test_custom_max_size(self):
        entries = self._make_entries([
            ("src/main.py", 100),
            ("src/medium.py", 5000),
        ])
        result = discover_source_files(entries, max_size=1000)
        assert result == ["src/main.py"]

    def test_multiple_languages(self):
        entries = self._make_entries([
            ("src/main.py", 100),
            ("src/app.js", 100),
            ("src/server.go", 100),
            ("src/lib.rs", 100),
        ])
        result = discover_source_files(entries)
        assert len(result) == 4

    def test_binary_extensions_filtered(self):
        entries = self._make_entries([
            ("src/main.py", 100),
            ("src/image.png", 5000),
            ("src/app.exe", 10000),
        ])
        result = discover_source_files(entries)
        # .png and .exe are not in LANGUAGE_EXTENSIONS so they're filtered by ext
        assert result == ["src/main.py"]


class TestSkipPatternsTraversal:
    """Discovery must skip paths containing '..' segments."""

    def test_dot_dot_in_path_skipped(self):
        from ironmunch.discovery import should_skip_file
        assert should_skip_file("src/../etc/passwd") is True

    def test_dot_dot_at_start_skipped(self):
        from ironmunch.discovery import should_skip_file
        assert should_skip_file("../../etc/passwd") is True
