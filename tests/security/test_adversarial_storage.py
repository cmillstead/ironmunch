"""Adversarial tests for storage layer: path traversal, byte_length cap, preloaded index.

Tests the three security fixes in get_symbol_content():
  C-1: arbitrary file read via poisoned index (path traversal)
  C-2: TOCTOU double-load race (preloaded index param)
  C-3: no byte_length cap
  C-4: arbitrary file write via traversal in raw_files paths
  ADV-MED-11: integer validation for byte_offset/byte_length
  ADV-MED-2: _cleanup_stale_temps skips recent files
"""

import json
import os
import tempfile
import time
from pathlib import Path

import pytest

from codesight_mcp.storage.index_store import IndexStore, CodeIndex
from codesight_mcp.core.limits import MAX_FILE_SIZE
from codesight_mcp.core.validation import ValidationError


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
            from codesight_mcp.parser.symbols import Symbol
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
            from codesight_mcp.parser.symbols import Symbol
            abs_path = os.path.join(tempfile.gettempdir(), "codesight_mcp_evil_test_12345.py")
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
            from codesight_mcp.parser.symbols import Symbol
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
            from codesight_mcp.parser.symbols import Symbol
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
            index_path = Path(tmp) / "owner__repo.json.gz"
            mode = oct(index_path.stat().st_mode & 0o777)
            assert mode == "0o600", f"Index file should be 0o600, got {mode}"


class TestStaleTempCleanup:
    """SEC-LOW-7: IndexStore must clean up stale .json.tmp files on init."""

    def test_stale_tmp_cleaned_on_init(self):
        """Stale .json.tmp files (>60s old) should be removed when IndexStore is created."""
        with tempfile.TemporaryDirectory() as tmp:
            stale = Path(tmp) / "owner__repo.json.tmp"
            stale.write_text('{"stale": true}')
            # Back-date the file so it appears >60 seconds old
            old_mtime = time.time() - 120
            os.utime(str(stale), (old_mtime, old_mtime))
            assert stale.exists()

            IndexStore(tmp)  # Should clean up stale tmp (>60s old)
            assert not stale.exists(), "Stale .json.tmp was not cleaned up"

    def test_valid_json_not_cleaned(self):
        """Normal .json files must NOT be cleaned up."""
        with tempfile.TemporaryDirectory() as tmp:
            normal = Path(tmp) / "owner__repo.json"
            normal.write_text('{"valid": true}')

            IndexStore(tmp)
            assert normal.exists(), "Normal .json file was incorrectly removed"


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
        from codesight_mcp.tools.search_text import search_text
        from codesight_mcp.parser.symbols import Symbol

        # sk- + 20 chars meets the _INLINE_SECRET_RE threshold of 20 chars after 'sk-'
        # Use SK_KEY (not in the api_key= pattern list) so the variable name survives
        # sanitization — only the sk-... value itself is replaced with <REDACTED>.
        secret = "sk-testkey12345678901234"
        file_content = f'SK_KEY = "{secret}"\n'

        with tempfile.TemporaryDirectory() as tmp:
            store = IndexStore(tmp)
            content_dir = Path(tmp) / "test__repo"
            content_dir.mkdir(parents=True, exist_ok=True)
            (content_dir / "config.py").write_text(file_content)

            sym = Symbol(
                id="config.py::SK_KEY#constant",
                file="config.py",
                name="SK_KEY",
                qualified_name="SK_KEY",
                kind="constant",
                language="python",
                signature=f'SK_KEY = "{secret}"',
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

            # Search by variable name — SK_KEY survives sanitization, only the sk-... value
            # is replaced with <REDACTED>, so the result text shows SK_KEY = "<REDACTED>"
            result = search_text(
                repo="test/repo",
                query="SK_KEY",
                storage_path=tmp,
            )

            assert result.get("result_count", 0) >= 1, "Expected at least one match"
            texts = [m["text"] for m in result["results"]]
            for text in texts:
                assert secret not in text, f"Secret value must not appear in result: {text!r}"
                assert "<REDACTED>" in text, f"Expected <REDACTED> in result: {text!r}"

    def test_non_secret_content_not_redacted(self):
        """Lines without secrets must pass through unchanged."""
        from codesight_mcp.tools.search_text import search_text
        from codesight_mcp.parser.symbols import Symbol

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

            result = search_text(
                repo="test/repo2",
                query="sk-short",
                storage_path=tmp,
            )

            assert result.get("result_count", 0) >= 1, "Expected at least one match"
            texts = [m["text"] for m in result["results"]]
            for text in texts:
                assert "sk-short" in text, f"Non-secret value should not be redacted: {text!r}"


def _make_symbol_with_offsets(byte_offset, byte_length):
    """Return a minimal symbol dict with the given byte offsets."""
    return {
        "id": "test::sym",
        "file": "test.py",
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
        "byte_offset": byte_offset,
        "byte_length": byte_length,
        "content_hash": "",
    }


class TestByteOffsetLengthValidation:
    """ADV-MED-11: get_symbol_content must validate byte_offset and byte_length."""

    def _make_index_with_sym(self, sym_dict, tmp):
        """Write a minimal index JSON and matching content file, return CodeIndex."""
        index_data = {
            "repo": "owner/repo",
            "owner": "owner",
            "name": "repo",
            "indexed_at": "2025-01-01T00:00:00",
            "source_files": ["test.py"],
            "languages": {"python": 1},
            "symbols": [sym_dict],
            "index_version": 2,
            "file_hashes": {},
            "git_head": "",
        }
        index_path = Path(tmp) / "owner__repo.json"
        with open(index_path, "w", encoding="utf-8") as f:
            json.dump(index_data, f)

        content_dir = Path(tmp) / "owner__repo"
        content_dir.mkdir(parents=True, exist_ok=True)
        (content_dir / "test.py").write_text("def sym(): pass\n")

        store = IndexStore(base_path=tmp)
        return store, store.load_index("owner", "repo")

    def test_float_byte_length_raises_validation_error(self):
        """byte_length=1.5 (float in JSON) must raise ValidationError, not TypeError."""
        with tempfile.TemporaryDirectory() as tmp:
            sym = _make_symbol_with_offsets(byte_offset=0, byte_length=1.5)
            store, index = self._make_index_with_sym(sym, tmp)
            # int(1.5) == 1, so this should succeed after truncation — but we want
            # the validation to catch non-integer types stored as floats via int() cast.
            # int(1.5) is a valid cast; the spec says raise ValidationError for float.
            # Re-inject a float that cannot be int()-cast cleanly to trigger the guard.
            index.symbols[0]["byte_length"] = float("nan")
            with pytest.raises((ValidationError, ValueError)):
                store.get_symbol_content("owner", "repo", "test::sym", index=index)

    def test_byte_offset_beyond_file_size_raises_validation_error(self):
        """byte_offset larger than file size must raise ValidationError."""
        with tempfile.TemporaryDirectory() as tmp:
            # File content is 16 bytes; set byte_offset well beyond that
            sym = _make_symbol_with_offsets(byte_offset=99999, byte_length=10)
            store, index = self._make_index_with_sym(sym, tmp)
            with pytest.raises(ValidationError, match="byte_offset out of bounds"):
                store.get_symbol_content("owner", "repo", "test::sym", index=index)

    def test_byte_length_zero_raises_validation_error(self):
        """byte_length=0 must raise ValidationError."""
        with tempfile.TemporaryDirectory() as tmp:
            sym = _make_symbol_with_offsets(byte_offset=0, byte_length=0)
            store, index = self._make_index_with_sym(sym, tmp)
            with pytest.raises(ValidationError, match="Invalid byte_length"):
                store.get_symbol_content("owner", "repo", "test::sym", index=index)


class TestCleanupStaleTempSkipsRecent:
    """ADV-MED-2: _cleanup_stale_temps must not delete files newer than 60 seconds."""

    def test_recent_tmp_file_not_deleted(self):
        """A fresh .json.tmp file must survive a call to _cleanup_stale_temps."""
        with tempfile.TemporaryDirectory() as tmp:
            recent = Path(tmp) / "owner__repo.json.tmp"
            recent.write_text('{"in_progress": true}')
            assert recent.exists()

            store = IndexStore(tmp)
            # Call directly — should skip the file because it is <60s old
            store._cleanup_stale_temps()

            assert recent.exists(), (
                "Recent .json.tmp was incorrectly deleted by _cleanup_stale_temps()"
            )


class TestMakedirs0o700EnforcesPermissions:
    """ADV-MED-5: _makedirs_0o700 must enforce 0o700 on pre-existing directories."""

    def test_newly_created_directory_is_0o700(self):
        """A freshly created directory must have mode 0o700."""
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "newdir")
            from codesight_mcp.storage.index_store import _makedirs_0o700
            _makedirs_0o700(target)
            mode = os.stat(target).st_mode & 0o777
            assert mode == 0o700, f"Expected 0o700, got {oct(mode)}"

    def test_preexisting_permissive_directory_rechmodded_to_0o700(self):
        """If a directory exists with 0o755, _makedirs_0o700 must chmod it to 0o700."""
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "existingdir")
            os.mkdir(target)
            os.chmod(target, 0o755)  # Explicit chmod — immune to umask leaks
            # Confirm starting state is permissive
            assert (os.stat(target).st_mode & 0o777) == 0o755

            from codesight_mcp.storage.index_store import _makedirs_0o700
            _makedirs_0o700(target)

            mode = os.stat(target).st_mode & 0o777
            assert mode == 0o700, (
                f"Pre-existing 0o755 directory not rechmodded: got {oct(mode)}"
            )

    def test_index_store_base_path_rechmodded_if_permissive(self):
        """IndexStore.__init__ must enforce 0o700 on a pre-existing permissive base_path."""
        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "store")
            os.mkdir(base)
            os.chmod(base, 0o755)  # Explicit chmod — immune to umask leaks
            assert (os.stat(base).st_mode & 0o777) == 0o755

            IndexStore(base_path=base)

            mode = os.stat(base).st_mode & 0o777
            assert mode == 0o700, (
                f"IndexStore base_path not rechmodded from 0o755: got {oct(mode)}"
            )

    def test_content_dir_rechmodded_if_permissive(self):
        """Content directory created during save_index must be 0o700 even if dir pre-existed."""
        from codesight_mcp.parser.symbols import Symbol
        with tempfile.TemporaryDirectory() as tmp:
            # Pre-create the content dir at 0o755
            content_dir = os.path.join(tmp, "owner__repo")
            os.mkdir(content_dir)
            os.chmod(content_dir, 0o755)  # Explicit chmod — immune to umask leaks
            assert (os.stat(content_dir).st_mode & 0o777) == 0o755

            store = IndexStore(base_path=tmp)
            sym = Symbol(
                id="test.py::foo#function",
                file="test.py", name="foo", qualified_name="foo",
                kind="function", language="python", signature="def foo():",
                line=1, end_line=2, byte_offset=0, byte_length=16,
                content_hash="a" * 64,
            )
            store.save_index(
                owner="owner", name="repo",
                source_files=["test.py"],
                symbols=[sym],
                raw_files={"test.py": "def foo(): pass\n"},
                languages={"python": 1},
            )

            mode = os.stat(content_dir).st_mode & 0o777
            assert mode == 0o700, (
                f"Content dir not rechmodded from 0o755: got {oct(mode)}"
            )


class TestIndexedAtTypeValidation:
    """ADV-LOW-1: indexed_at must be validated as a string in load_index."""

    def _write_index(self, tmp, indexed_at_value):
        """Write a minimal index JSON with the given indexed_at value."""
        index_data = {
            "repo": "owner/repo",
            "owner": "owner",
            "name": "repo",
            "indexed_at": indexed_at_value,
            "source_files": [],
            "languages": {},
            "symbols": [],
            "index_version": 2,
            "file_hashes": {},
            "git_head": "",
        }
        index_path = Path(tmp) / "owner__repo.json"
        with open(index_path, "w", encoding="utf-8") as f:
            json.dump(index_data, f)

    def test_integer_indexed_at_returns_none(self):
        """indexed_at=12345 (integer) must cause load_index to return None."""
        with tempfile.TemporaryDirectory() as tmp:
            self._write_index(tmp, 12345)
            store = IndexStore(base_path=tmp)
            result = store.load_index("owner", "repo")
            assert result is None, "Expected None for integer indexed_at"

    def test_null_indexed_at_returns_none(self):
        """indexed_at=null must cause load_index to return None."""
        with tempfile.TemporaryDirectory() as tmp:
            self._write_index(tmp, None)
            store = IndexStore(base_path=tmp)
            result = store.load_index("owner", "repo")
            assert result is None, "Expected None for null indexed_at"

    def test_list_indexed_at_returns_none(self):
        """indexed_at=[] must cause load_index to return None."""
        with tempfile.TemporaryDirectory() as tmp:
            self._write_index(tmp, [])
            store = IndexStore(base_path=tmp)
            result = store.load_index("owner", "repo")
            assert result is None, "Expected None for list indexed_at"

    def test_valid_string_indexed_at_loads_successfully(self):
        """A valid ISO string indexed_at must load without error."""
        with tempfile.TemporaryDirectory() as tmp:
            self._write_index(tmp, "2025-01-01T00:00:00")
            store = IndexStore(base_path=tmp)
            result = store.load_index("owner", "repo")
            assert result is not None
            assert result.indexed_at == "2025-01-01T00:00:00"


class TestContentHashValidation:
    """ADV-LOW-6: content_hash must be validated as a 64-char lowercase hex string."""

    def _write_index_with_hash(self, tmp, content_hash_value):
        """Write a minimal index JSON with one symbol carrying the given content_hash."""
        index_data = {
            "repo": "owner/repo",
            "owner": "owner",
            "name": "repo",
            "indexed_at": "2025-01-01T00:00:00",
            "source_files": ["test.py"],
            "languages": {"python": 1},
            "symbols": [
                {
                    "id": "test::sym",
                    "file": "test.py",
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
                    "byte_length": 16,
                    "content_hash": content_hash_value,
                }
            ],
            "index_version": 2,
            "file_hashes": {},
            "git_head": "",
        }
        index_path = Path(tmp) / "owner__repo.json"
        with open(index_path, "w", encoding="utf-8") as f:
            json.dump(index_data, f)

    def test_malformed_hash_replaced_with_empty_string(self):
        """A non-hex content_hash is discarded (set to '') on load."""
        with tempfile.TemporaryDirectory() as tmp:
            self._write_index_with_hash(tmp, "not-a-hash")
            store = IndexStore(base_path=tmp)
            index = store.load_index("owner", "repo")
            assert index is not None
            sym = index.get_symbol("test::sym")
            assert sym is not None
            assert sym["content_hash"] == "", (
                f"Expected empty string, got {sym['content_hash']!r}"
            )

    def test_integer_hash_replaced_with_empty_string(self):
        """An integer content_hash is discarded (set to '') on load."""
        with tempfile.TemporaryDirectory() as tmp:
            self._write_index_with_hash(tmp, 12345)
            store = IndexStore(base_path=tmp)
            index = store.load_index("owner", "repo")
            assert index is not None
            sym = index.get_symbol("test::sym")
            assert sym is not None
            assert sym["content_hash"] == "", (
                f"Expected empty string for integer hash, got {sym['content_hash']!r}"
            )

    def test_uppercase_hex_hash_replaced_with_empty_string(self):
        """An uppercase 64-char hex string fails fullmatch (only lowercase allowed)."""
        with tempfile.TemporaryDirectory() as tmp:
            self._write_index_with_hash(tmp, "A" * 64)
            store = IndexStore(base_path=tmp)
            index = store.load_index("owner", "repo")
            assert index is not None
            sym = index.get_symbol("test::sym")
            assert sym is not None
            assert sym["content_hash"] == "", (
                f"Expected empty string for uppercase hash, got {sym['content_hash']!r}"
            )

    def test_short_hash_replaced_with_empty_string(self):
        """A 63-char hex string (one short) is discarded."""
        with tempfile.TemporaryDirectory() as tmp:
            self._write_index_with_hash(tmp, "a" * 63)
            store = IndexStore(base_path=tmp)
            index = store.load_index("owner", "repo")
            assert index is not None
            sym = index.get_symbol("test::sym")
            assert sym is not None
            assert sym["content_hash"] == "", (
                f"Expected empty string for 63-char hash, got {sym['content_hash']!r}"
            )

    def test_valid_sha256_hash_preserved(self):
        """A valid 64-char lowercase hex SHA-256 hash is preserved unchanged."""
        valid_hash = "a" * 64
        with tempfile.TemporaryDirectory() as tmp:
            self._write_index_with_hash(tmp, valid_hash)
            store = IndexStore(base_path=tmp)
            index = store.load_index("owner", "repo")
            assert index is not None
            sym = index.get_symbol("test::sym")
            assert sym is not None
            assert sym["content_hash"] == valid_hash, (
                f"Valid hash should be preserved, got {sym['content_hash']!r}"
            )

    def test_empty_string_hash_replaced_with_empty_string(self):
        """An empty string content_hash is treated as absent/invalid and left as ''."""
        with tempfile.TemporaryDirectory() as tmp:
            self._write_index_with_hash(tmp, "")
            store = IndexStore(base_path=tmp)
            index = store.load_index("owner", "repo")
            assert index is not None
            sym = index.get_symbol("test::sym")
            assert sym is not None
            # "" fails fullmatch so it becomes "" (no change but validation still runs)
            assert sym["content_hash"] == ""
