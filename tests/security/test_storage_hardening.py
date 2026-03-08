"""Tests for storage identifier hardening."""

import json
import os
import tempfile
from pathlib import Path

import pytest

from codesight_mcp.storage.index_store import IndexStore
from codesight_mcp.core.validation import ValidationError


class TestIdentifierSanitization:
    def test_normal_identifiers(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = IndexStore(tmp)
            path = store._index_path("owner", "repo")
            assert "owner__repo.json" in str(path)

    def test_traversal_in_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = IndexStore(tmp)
            with pytest.raises(ValidationError):
                store._index_path("..", "repo")

    def test_slash_in_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = IndexStore(tmp)
            with pytest.raises(ValidationError):
                store._index_path("owner", "repo/../../etc")

    def test_null_byte_in_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = IndexStore(tmp)
            with pytest.raises(ValidationError):
                store._index_path("owner\x00evil", "repo")

    def test_content_dir_same_sanitization(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = IndexStore(tmp)
            with pytest.raises(ValidationError):
                store._content_dir("../escape", "repo")


class TestIndexSizeValidation:
    def test_oversized_index_rejected(self):
        """Index files exceeding MAX_INDEX_SIZE are rejected on load."""
        with tempfile.TemporaryDirectory() as tmp:
            store = IndexStore(tmp)

            # Save a valid index first
            store.save_index(
                owner="test",
                name="repo",
                source_files=["main.py"],
                symbols=[],
                raw_files={"main.py": ""},
                languages={"python": 1},
            )

            # Bloat the index file beyond the limit
            index_path = store._index_path("test", "repo")
            with open(index_path, "r") as f:
                data = json.load(f)

            # Pad with junk to exceed 50 MB
            from codesight_mcp.core.limits import MAX_INDEX_SIZE
            data["_pad"] = "x" * (MAX_INDEX_SIZE + 1)
            with open(index_path, "w") as f:
                json.dump(data, f)

            with pytest.raises(ValueError, match="exceeds maximum size"):
                store.load_index("test", "repo")

    def test_normal_size_index_loads(self):
        """Index files within the size limit load normally."""
        with tempfile.TemporaryDirectory() as tmp:
            store = IndexStore(tmp)

            store.save_index(
                owner="test",
                name="repo",
                source_files=["main.py"],
                symbols=[],
                raw_files={"main.py": ""},
                languages={"python": 1},
            )

            loaded = store.load_index("test", "repo")
            assert loaded is not None
            assert loaded.repo == "test/repo"


class TestIncrementalSaveDeletedFilesTraversal:
    """SEC-HIGH-1: Verify traversal in deleted_files is blocked."""

    def test_traversal_in_deleted_files_blocked(self):
        """Deleted files with traversal paths must not delete outside content dir."""
        with tempfile.TemporaryDirectory() as tmp:
            store = IndexStore(tmp)

            # Create an initial index
            store.save_index(
                owner="test", name="repo",
                source_files=["main.py"],
                symbols=[], raw_files={"main.py": "print('hello')"},
                languages={"python": 1},
            )

            # Place a target file at the traversal destination
            target = Path(tmp) / "victim.txt"
            target.write_text("precious data")

            # Attempt incremental save with traversal in deleted_files
            store.incremental_save(
                owner="test", name="repo",
                changed_files=[], new_files=[],
                deleted_files=["../../victim.txt", "../victim.txt"],
                new_symbols=[], raw_files={},
                languages={"python": 1},
            )

            # Target file must survive
            assert target.exists(), "Traversal in deleted_files escaped content dir"
            assert target.read_text() == "precious data"

    def test_legitimate_deleted_files_still_work(self):
        """Normal file deletion in incremental save still works."""
        with tempfile.TemporaryDirectory() as tmp:
            store = IndexStore(tmp)

            store.save_index(
                owner="test", name="repo",
                source_files=["old.py"],
                symbols=[], raw_files={"old.py": "# old"},
                languages={"python": 1},
            )

            content_dir = store._content_dir("test", "repo")
            old_file = content_dir / "old.py"
            assert old_file.exists()

            store.incremental_save(
                owner="test", name="repo",
                changed_files=[], new_files=[],
                deleted_files=["old.py"],
                new_symbols=[], raw_files={},
                languages={"python": 1},
            )

            assert not old_file.exists(), "Legitimate deleted file should be removed"


class TestBasePathPermissions:
    """SEC-LOW-4: IndexStore base_path must be created with 0o700 permissions."""

    def test_base_path_mode_is_0o700(self):
        """base_path must have mode 0o700 after IndexStore construction."""
        with tempfile.TemporaryDirectory() as storage_tmp:
            base = Path(storage_tmp) / "idx"
            store = IndexStore(base_path=str(base))
            mode = os.stat(str(base)).st_mode & 0o777
            assert mode == 0o700, (
                f"base_path mode should be 0o700, got 0o{mode:o}"
            )


class TestLoadIndexNoFollow:
    """SEC-LOW-2: load_index must reject symlinks (O_NOFOLLOW)."""

    def test_symlink_index_returns_none(self):
        """load_index must return None when the index file is a symlink."""
        with tempfile.TemporaryDirectory() as storage_tmp:
            with tempfile.TemporaryDirectory() as other_tmp:
                store = IndexStore(base_path=storage_tmp)

                # Create a real index file first
                store.save_index(
                    owner="test", name="repo",
                    source_files=["main.py"],
                    symbols=[], raw_files={"main.py": "x = 1"},
                    languages={"python": 1},
                )

                # Locate the real index file and replace it with a symlink
                index_file = Path(storage_tmp) / "test__repo.json"
                assert index_file.exists()
                decoy = Path(other_tmp) / "decoy.txt"
                decoy.write_text("not a valid index")
                index_file.unlink()
                index_file.symlink_to(decoy)

                # load_index must return None rather than reading the symlink target
                result = store.load_index("test", "repo")
                assert result is None, (
                    "load_index must return None for a symlink index file"
                )


class TestLoadIndexElementValidation:
    """SEC-LOW-2: load_index must validate element types within lists and dicts."""

    def test_source_files_non_string_element_rejected(self):
        """source_files with a non-string element must cause load_index to return None."""
        with tempfile.TemporaryDirectory() as storage:
            store = IndexStore(storage)
            index_path = (
                store.base_path / "test__repo.json"
            )
            malformed = {
                "repo": "test/repo",
                "owner": "test",
                "name": "repo",
                "indexed_at": "2026-01-01T00:00:00",
                "source_files": ["valid.py", None, 42],
                "symbols": [],
                "languages": {"python": 1},
                "file_count": 1,
                "symbol_count": 0,
            }
            index_path.write_text(json.dumps(malformed), encoding="utf-8")
            result = store.load_index("test", "repo")
            assert result is None, "Expected None for source_files with non-string elements"

    def test_languages_non_int_value_rejected(self):
        """languages dict with non-integer value must cause load_index to return None."""
        with tempfile.TemporaryDirectory() as storage:
            store = IndexStore(storage)
            index_path = store.base_path / "test__repo2.json"
            malformed = {
                "repo": "test/repo2",
                "owner": "test",
                "name": "repo2",
                "indexed_at": "2026-01-01T00:00:00",
                "source_files": ["valid.py"],
                "symbols": [],
                "languages": {"python": "not-an-int"},
                "file_count": 1,
                "symbol_count": 0,
            }
            index_path.write_text(json.dumps(malformed), encoding="utf-8")
            result = store.load_index("test", "repo2")
            assert result is None, "Expected None for languages with non-integer value"


class TestLoadIndexResanitization:
    """SEC-LOW-5: load_index must re-apply secret redaction to loaded symbol fields."""

    def test_secret_in_signature_redacted_on_load(self):
        """A secret token in a stored symbol signature must be redacted on load."""
        with tempfile.TemporaryDirectory() as storage:
            store = IndexStore(storage)
            index_path = store.base_path / "test__resanitize.json"
            secret = "sk_live_" + "x" * 24
            malformed = {
                "repo": "test/resanitize",
                "owner": "test",
                "name": "resanitize",
                "indexed_at": "2026-01-01T00:00:00",
                "source_files": ["main.py"],
                "symbols": [{
                    "id": "main.py::foo",
                    "file": "main.py",
                    "name": "foo",
                    "qualified_name": "foo",
                    "kind": "function",
                    "language": "python",
                    "signature": f"def foo(key='{secret}'):",
                    "docstring": f"Uses key={secret}",
                    "summary": f"Function with key {secret}",
                    "decorators": [],
                    "line": 1,
                    "end_line": 2,
                    "byte_offset": 0,
                    "byte_length": 20,
                    "content_hash": "abc123",
                }],
                "languages": {"python": 1},
                "file_count": 1,
                "symbol_count": 1,
            }
            index_path.write_text(json.dumps(malformed), encoding="utf-8")
            idx = store.load_index("test", "resanitize")
            assert idx is not None
            sym = idx.symbols[0]
            assert secret not in sym.get("signature", ""), "Secret in signature after load"
            assert secret not in sym.get("docstring", ""), "Secret in docstring after load"
            assert secret not in sym.get("summary", ""), "Secret in summary after load"


class TestTempFileONofollow:
    """SEC-LOW-8: temp-file writes must refuse to follow symlinks."""

    def test_save_index_rejects_symlink_at_tmp_path(self, tmp_path):
        """save_index must raise OSError if a symlink exists at the .json.tmp path."""
        import sys

        if sys.platform == "win32":
            pytest.skip("O_NOFOLLOW not available on Windows")

        store = IndexStore(base_path=str(tmp_path))
        tmp_file = tmp_path / "local__testrepo.json.tmp"
        decoy = tmp_path / "decoy.txt"
        decoy.write_text("decoy content")
        tmp_file.symlink_to(decoy)

        # Attempt to save — must fail with OSError (ELOOP) not silently follow symlink
        with pytest.raises(OSError):
            store.save_index(
                owner="local",
                name="testrepo",
                source_files=["x.py"],
                symbols=[],
                raw_files={"x.py": "x = 1"},
                languages={"python": 1},
            )
