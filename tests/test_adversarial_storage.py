"""Adversarial tests for storage layer: path traversal, byte_length cap, preloaded index.

Tests the three security fixes in get_symbol_content():
  C-1: arbitrary file read via poisoned index (path traversal)
  C-2: TOCTOU double-load race (preloaded index param)
  C-3: no byte_length cap
  C-4: arbitrary file write via traversal in raw_files paths
"""

import json
import os
import tempfile
from pathlib import Path

import pytest

from ironmunch.storage.index_store import IndexStore, CodeIndex
from ironmunch.core.limits import MAX_FILE_SIZE


def _make_poisoned_index(
    tmp: str,
    owner: str,
    name: str,
    poison_path: str,
    byte_length: int = 50,
) -> None:
    """Create a minimal index JSON with one symbol pointing at poison_path.

    Also creates the content dir so the store can find it.
    """
    index_data = {
        "repo": f"{owner}/{name}",
        "owner": owner,
        "name": name,
        "indexed_at": "2025-01-01T00:00:00",
        "source_files": [poison_path],
        "languages": {"python": 1},
        "symbols": [
            {
                "id": "poisoned::sym",
                "file": poison_path,
                "name": "sym",
                "qualified_name": "sym",
                "kind": "function",
                "language": "python",
                "signature": "def sym():",
                "docstring": "",
                "summary": "",
                "decorators": [],
                "keywords": [],
                "parent": None,
                "line": 1,
                "end_line": 2,
                "byte_offset": 0,
                "byte_length": byte_length,
                "content_hash": "",
            }
        ],
        "index_version": 2,
        "file_hashes": {},
        "git_head": "",
    }

    index_path = Path(tmp) / f"{owner}__{name}.json"
    with open(index_path, "w", encoding="utf-8") as f:
        json.dump(index_data, f)

    # Create the content directory (may or may not contain the poisoned file)
    content_dir = Path(tmp) / f"{owner}__{name}"
    content_dir.mkdir(parents=True, exist_ok=True)


class TestGetSymbolContentTraversal:
    """C-1: poisoned index should not allow reading arbitrary files."""

    def test_dotdot_traversal_returns_none(self):
        """../../etc/passwd path traversal must return None."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_poisoned_index(tmp, "owner", "repo", "../../etc/passwd")
            store = IndexStore(base_path=tmp)
            result = store.get_symbol_content("owner", "repo", "poisoned::sym")
            assert result is None

    def test_absolute_path_returns_none(self):
        """/etc/passwd absolute path must return None."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_poisoned_index(tmp, "owner", "repo", "/etc/passwd")
            store = IndexStore(base_path=tmp)
            result = store.get_symbol_content("owner", "repo", "poisoned::sym")
            assert result is None

    def test_dotgit_config_returns_none(self):
        """.git/config (dot-prefixed segment) must return None."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_poisoned_index(tmp, "owner", "repo", ".git/config")
            store = IndexStore(base_path=tmp)
            result = store.get_symbol_content("owner", "repo", "poisoned::sym")
            assert result is None

    def test_symlink_escape_returns_none(self):
        """Symlink pointing outside content dir must return None."""
        with tempfile.TemporaryDirectory() as tmp:
            # Create an "escape" directory outside the content dir
            escape_dir = Path(tmp) / "escape"
            escape_dir.mkdir()
            target = escape_dir / "target.py"
            target.write_text("SECRET = 'leaked'")

            _make_poisoned_index(tmp, "owner", "repo", "link/target.py")

            content_dir = Path(tmp) / "owner__repo"
            # Create a symlink "link" that points outside the content dir
            symlink_dir = content_dir / "link"
            symlink_dir.symlink_to(str(escape_dir))

            store = IndexStore(base_path=tmp)
            result = store.get_symbol_content("owner", "repo", "poisoned::sym")
            assert result is None

    def test_null_byte_injection_returns_none(self):
        """Path with null byte must return None."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_poisoned_index(tmp, "owner", "repo", "safe.py\x00../../etc/passwd")
            store = IndexStore(base_path=tmp)
            result = store.get_symbol_content("owner", "repo", "poisoned::sym")
            assert result is None


class TestGetSymbolContentByteLengthCap:
    """C-3: byte_length from untrusted index must be capped to MAX_FILE_SIZE."""

    def test_huge_byte_length_is_capped(self):
        """byte_length=2_147_483_647 should be capped to MAX_FILE_SIZE."""
        with tempfile.TemporaryDirectory() as tmp:
            huge_len = 2_147_483_647
            _make_poisoned_index(tmp, "owner", "repo", "test.py", byte_length=huge_len)

            # Write a small legitimate file
            content_dir = Path(tmp) / "owner__repo"
            test_file = content_dir / "test.py"
            file_content = "x" * 100
            test_file.write_text(file_content)

            store = IndexStore(base_path=tmp)
            result = store.get_symbol_content("owner", "repo", "poisoned::sym")

            # Result should exist (file is legitimate) but be at most MAX_FILE_SIZE bytes
            assert result is not None
            assert len(result.encode("utf-8")) <= MAX_FILE_SIZE

    def test_normal_byte_length_unchanged(self):
        """A normal byte_length within limits should read correctly."""
        with tempfile.TemporaryDirectory() as tmp:
            content = "def foo():\n    pass\n"
            _make_poisoned_index(
                tmp, "owner", "repo", "test.py",
                byte_length=len(content.encode("utf-8")),
            )

            content_dir = Path(tmp) / "owner__repo"
            (content_dir / "test.py").write_text(content)

            store = IndexStore(base_path=tmp)
            result = store.get_symbol_content("owner", "repo", "poisoned::sym")

            assert result is not None
            assert result == content


class TestGetSymbolContentAcceptsPreloadedIndex:
    """C-2: passing index= avoids TOCTOU double-load."""

    def test_preloaded_index_is_used(self):
        """When index= is passed, the store should not re-load from disk."""
        with tempfile.TemporaryDirectory() as tmp:
            content = "def bar():\n    return 42\n"

            # Write content file but no index JSON
            content_dir = Path(tmp) / "owner__repo"
            content_dir.mkdir(parents=True)
            (content_dir / "test.py").write_text(content)

            # Build a CodeIndex in memory
            index = CodeIndex(
                repo="owner/repo",
                owner="owner",
                name="repo",
                indexed_at="2025-01-01T00:00:00",
                source_files=["test.py"],
                languages={"python": 1},
                symbols=[
                    {
                        "id": "test::bar",
                        "file": "test.py",
                        "name": "bar",
                        "qualified_name": "bar",
                        "kind": "function",
                        "language": "python",
                        "signature": "def bar():",
                        "docstring": "",
                        "summary": "",
                        "decorators": [],
                        "keywords": [],
                        "parent": None,
                        "line": 1,
                        "end_line": 2,
                        "byte_offset": 0,
                        "byte_length": len(content.encode("utf-8")),
                        "content_hash": "",
                    }
                ],
            )

            store = IndexStore(base_path=tmp)
            # No index JSON on disk, but passing index= should work
            result = store.get_symbol_content(
                "owner", "repo", "test::bar", index=index
            )
            assert result is not None
            assert "def bar():" in result

    def test_preloaded_index_none_falls_back_to_load(self):
        """When index=None, it should load from disk (backward compat)."""
        with tempfile.TemporaryDirectory() as tmp:
            content = "def baz(): pass\n"
            _make_poisoned_index(
                tmp, "owner", "repo", "test.py",
                byte_length=len(content.encode("utf-8")),
            )

            content_dir = Path(tmp) / "owner__repo"
            (content_dir / "test.py").write_text(content)

            store = IndexStore(base_path=tmp)
            # index=None (default) should load from disk
            result = store.get_symbol_content("owner", "repo", "poisoned::sym")
            assert result is not None
            assert "def baz():" in result


class TestSaveIndexPathTraversal:
    """C-4: raw_files paths must not write outside content directory."""

    def test_traversal_in_raw_files_blocked(self):
        """raw_files with '../../evil.py' must not write outside content dir."""
        with tempfile.TemporaryDirectory() as tmp:
            from ironmunch.parser.symbols import Symbol
            traversal_path = "../../evil.py"
            symbols = [Symbol(
                id=f"{traversal_path}::main#function",
                file=traversal_path, name="main", qualified_name="main",
                kind="function", language="python", signature="def main():",
                line=1, end_line=2, byte_offset=0, byte_length=17,
                content_hash="a" * 64,
            )]
            store = IndexStore(tmp)
            store.save_index(
                owner="test", name="repo",
                source_files=[traversal_path],
                symbols=symbols,
                raw_files={traversal_path: "def main(): pass"},
                languages={"python": 1},
            )
            # The evil file must NOT exist outside the content dir
            evil_path = (Path(tmp) / ".." / "evil.py").resolve()
            assert not evil_path.exists(), "Traversal write escaped content dir!"

    def test_absolute_path_in_raw_files_blocked(self):
        """raw_files with absolute path must not write outside content dir."""
        with tempfile.TemporaryDirectory() as tmp:
            from ironmunch.parser.symbols import Symbol
            abs_path = os.path.join(tempfile.gettempdir(), "ironmunch_evil_test_12345.py")
            symbols = [Symbol(
                id=f"{abs_path}::main#function",
                file=abs_path, name="main", qualified_name="main",
                kind="function", language="python", signature="def main():",
                line=1, end_line=2, byte_offset=0, byte_length=17,
                content_hash="a" * 64,
            )]
            store = IndexStore(tmp)
            store.save_index(
                owner="test", name="repo",
                source_files=[abs_path],
                symbols=symbols,
                raw_files={abs_path: "def main(): pass"},
                languages={"python": 1},
            )
            assert not Path(abs_path).exists(), "Absolute path write escaped!"

    def test_traversal_in_incremental_save_blocked(self):
        """incremental_save with traversal path must not write outside content dir."""
        with tempfile.TemporaryDirectory() as tmp:
            from ironmunch.parser.symbols import Symbol
            # First create a valid index to update
            safe_sym = Symbol(
                id="safe.py::safe#function",
                file="safe.py", name="safe", qualified_name="safe",
                kind="function", language="python", signature="def safe():",
                line=1, end_line=2, byte_offset=0, byte_length=16,
                content_hash="b" * 64,
            )
            store = IndexStore(tmp)
            store.save_index(
                owner="test", name="repo",
                source_files=["safe.py"],
                symbols=[safe_sym],
                raw_files={"safe.py": "def safe(): pass"},
                languages={"python": 1},
            )

            # Now do an incremental save with a traversal path
            traversal_path = "../../evil_incremental.py"
            evil_sym = Symbol(
                id=f"{traversal_path}::evil#function",
                file=traversal_path, name="evil", qualified_name="evil",
                kind="function", language="python", signature="def evil():",
                line=1, end_line=2, byte_offset=0, byte_length=17,
                content_hash="c" * 64,
            )
            store.incremental_save(
                owner="test", name="repo",
                changed_files=[],
                new_files=[traversal_path],
                deleted_files=[],
                new_symbols=[evil_sym],
                raw_files={traversal_path: "def evil(): pass"},
                languages={"python": 1},
            )
            evil_path = (Path(tmp) / ".." / "evil_incremental.py").resolve()
            assert not evil_path.exists(), "Incremental traversal write escaped!"


class TestSafeWriteContentSymlink:
    """SEC-MED-2: _safe_write_content must reject symlink destinations."""

    def test_symlink_write_rejected(self):
        """Writing to a symlink should return False (O_NOFOLLOW)."""
        with tempfile.TemporaryDirectory() as tmp:
            store = IndexStore(tmp)
            content_dir = Path(tmp) / "owner__repo"
            content_dir.mkdir()

            # Create a symlink target outside content dir
            escape_dir = Path(tmp) / "escape"
            escape_dir.mkdir()
            target = escape_dir / "evil.py"

            # Create a symlink inside content dir pointing to escape
            symlink = content_dir / "evil.py"
            symlink.symlink_to(str(target))

            # _safe_write_content should refuse to follow the symlink
            result = store._safe_write_content(content_dir, "evil.py", "malicious content")
            assert result is False, "O_NOFOLLOW should reject symlink write"
            assert not target.exists(), "Content must not be written through symlink"

    def test_normal_write_succeeds(self):
        """Normal (non-symlink) write should succeed."""
        with tempfile.TemporaryDirectory() as tmp:
            store = IndexStore(tmp)
            content_dir = Path(tmp) / "owner__repo"
            content_dir.mkdir()

            result = store._safe_write_content(content_dir, "test.py", "def hello(): pass")
            assert result is True
            assert (content_dir / "test.py").read_text() == "def hello(): pass"

    def test_temp_file_permissions(self):
        """Temp files created during save_index should have 0o600 permissions."""
        with tempfile.TemporaryDirectory() as tmp:
            from ironmunch.parser.symbols import Symbol
            sym = Symbol(
                id="test.py::foo#function",
                file="test.py", name="foo", qualified_name="foo",
                kind="function", language="python", signature="def foo():",
                line=1, end_line=2, byte_offset=0, byte_length=16,
                content_hash="a" * 64,
            )
            store = IndexStore(tmp)
            store.save_index(
                owner="owner", name="repo",
                source_files=["test.py"],
                symbols=[sym],
                raw_files={"test.py": "def foo(): pass\n"},
                languages={"python": 1},
            )
            index_path = Path(tmp) / "owner__repo.json"
            mode = oct(index_path.stat().st_mode & 0o777)
            assert mode == "0o600", f"Index file should be 0o600, got {mode}"


class TestStaleTempCleanup:
    """SEC-LOW-7: IndexStore must clean up stale .json.tmp files on init."""

    def test_stale_tmp_cleaned_on_init(self):
        """Stale .json.tmp files should be removed when IndexStore is created."""
        with tempfile.TemporaryDirectory() as tmp:
            stale = Path(tmp) / "owner__repo.json.tmp"
            stale.write_text('{"stale": true}')
            assert stale.exists()

            IndexStore(tmp)  # Should clean up stale tmp
            assert not stale.exists(), "Stale .json.tmp was not cleaned up"

    def test_valid_json_not_cleaned(self):
        """Normal .json files must NOT be cleaned up."""
        with tempfile.TemporaryDirectory() as tmp:
            normal = Path(tmp) / "owner__repo.json"
            normal.write_text('{"valid": true}')

            IndexStore(tmp)
            assert normal.exists(), "Normal .json file was incorrectly removed"


import ironmunch.core.roots as roots_mod
from ironmunch.core.roots import init_storage_root, get_storage_root, RootNotInitializedError


class TestIndexSchemaValidation:
    """M-1: Malformed index JSON must be handled gracefully."""

    def test_missing_required_fields_returns_none(self):
        """Index with missing fields must not crash."""
        with tempfile.TemporaryDirectory() as tmp:
            index_path = Path(tmp) / "bad__index.json"
            index_path.write_text('{"repo": "bad/index"}')  # Missing most fields

            store = IndexStore(tmp)
            result = store.load_index("bad", "index")
            assert result is None

    def test_wrong_types_returns_none(self):
        """Index with wrong field types must not crash."""
        with tempfile.TemporaryDirectory() as tmp:
            index_path = Path(tmp) / "bad__index.json"
            index_path.write_text(json.dumps({
                "repo": 12345,  # should be string
                "owner": None,
                "name": [],
                "indexed_at": False,
                "source_files": "not a list",
                "languages": "not a dict",
                "symbols": "not a list",
                "index_version": "two",
            }))

            store = IndexStore(tmp)
            result = store.load_index("bad", "index")
            assert result is None


class TestImmutableRoot:
    """M-8: init_storage_root must only be callable once."""

    def test_double_init_raises(self):
        """Second call to init_storage_root must raise."""
        old = roots_mod._storage_root
        roots_mod._storage_root = None
        try:
            with tempfile.TemporaryDirectory() as tmp:
                init_storage_root(tmp)
                with pytest.raises(RuntimeError, match="already initialized"):
                    init_storage_root(tmp)
        finally:
            roots_mod._storage_root = old


class TestListReposValidation:
    """M-9: list_repos must skip malformed JSON files."""

    def test_non_index_json_skipped(self):
        """Random JSON files in base_path must not appear in results."""
        with tempfile.TemporaryDirectory() as tmp:
            # Create a non-index JSON file
            (Path(tmp) / "random.json").write_text('{"not": "an index"}')

            store = IndexStore(tmp)
            repos = store.list_repos()
            # Should not crash, and should not include the random file
            for r in repos:
                assert "repo" in r


class TestSearchTextSecretRedaction:
    """SEC-MED-5: search_text must redact inline secrets from matching lines."""

    def test_secret_value_redacted_in_results(self):
        """Matching lines containing hardcoded secrets must have secret value redacted."""
        from ironmunch.tools.search_text import search_text
        from ironmunch.parser.symbols import Symbol

        # sk- + 20 chars meets the _INLINE_SECRET_RE threshold of 20 chars after 'sk-'
        secret = "sk-testkey12345678901234"
        file_content = f'API_KEY = "{secret}"\n'

        with tempfile.TemporaryDirectory() as tmp:
            store = IndexStore(tmp)
            content_dir = Path(tmp) / "test__repo"
            content_dir.mkdir(parents=True, exist_ok=True)
            (content_dir / "config.py").write_text(file_content)

            sym = Symbol(
                id="config.py::API_KEY#constant",
                file="config.py",
                name="API_KEY",
                qualified_name="API_KEY",
                kind="constant",
                language="python",
                signature=f'API_KEY = "{secret}"',
                line=1, end_line=1,
                byte_offset=0,
                byte_length=len(file_content.encode("utf-8")),
                content_hash="a" * 64,
            )
            store.save_index(
                owner="test", name="repo",
                source_files=["config.py"],
                symbols=[sym],
                raw_files={"config.py": file_content},
                languages={"python": 1},
            )

            result = search_text(repo="test/repo", query="sk-", storage_path=tmp)

            assert result.get("result_count", 0) >= 1, "Expected at least one match"
            texts = [m["text"] for m in result["results"]]
            for text in texts:
                assert secret not in text, f"Secret value must not appear in result: {text!r}"
                assert "<REDACTED>" in text, f"Expected <REDACTED> in result: {text!r}"

    def test_non_secret_content_not_redacted(self):
        """Lines without secrets must pass through unchanged."""
        from ironmunch.tools.search_text import search_text
        from ironmunch.parser.symbols import Symbol

        file_content = 'prefix = "sk-short"\n'  # Only 5 chars after sk- — not redacted

        with tempfile.TemporaryDirectory() as tmp:
            store = IndexStore(tmp)
            content_dir = Path(tmp) / "test__repo2"
            content_dir.mkdir(parents=True, exist_ok=True)
            (content_dir / "safe.py").write_text(file_content)

            sym = Symbol(
                id="safe.py::prefix#constant",
                file="safe.py",
                name="prefix",
                qualified_name="prefix",
                kind="constant",
                language="python",
                signature='prefix = "sk-short"',
                line=1, end_line=1,
                byte_offset=0,
                byte_length=len(file_content.encode("utf-8")),
                content_hash="b" * 64,
            )
            store.save_index(
                owner="test", name="repo2",
                source_files=["safe.py"],
                symbols=[sym],
                raw_files={"safe.py": file_content},
                languages={"python": 1},
            )

            result = search_text(repo="test/repo2", query="sk-short", storage_path=tmp)

            assert result.get("result_count", 0) >= 1, "Expected at least one match"
            texts = [m["text"] for m in result["results"]]
            for text in texts:
                assert "sk-short" in text, f"Non-secret value should not be redacted: {text!r}"
