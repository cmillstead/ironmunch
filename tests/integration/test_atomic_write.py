"""P0-08: Atomic write integrity tests.

Verify that interrupted or failed index writes leave no corrupted index
and that .tmp files are cleaned up properly.
"""

import gzip
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from codesight_mcp.parser import Symbol
from codesight_mcp.storage import IndexStore


def _make_symbol(name: str, src: str) -> Symbol:
    """Create a minimal Symbol for testing."""
    return Symbol(
        id=f"test.py::{name}#function",
        file="test.py",
        name=name,
        qualified_name=name,
        kind="function",
        language="python",
        signature=f"def {name}():",
        byte_offset=0,
        byte_length=len(src),
    )


def _save_simple_index(store: IndexStore, owner: str, name: str, sym_name: str = "foo"):
    """Save a simple single-symbol index and return the source string."""
    src = f"def {sym_name}():\n    return 42\n"
    symbols = [_make_symbol(sym_name, src)]
    store.save_index(
        owner=owner,
        name=name,
        source_files=["test.py"],
        symbols=symbols,
        raw_files={"test.py": src},
        languages={"python": 1},
    )
    return src


class TestCrashDuringSecondSave:
    """Simulate a crash during Phase 3 (_atomic_write) of a second save_index.

    The original index must remain loadable and intact.
    """

    def test_original_index_survives_rename_failure(self, tmp_path):
        """If os.replace raises during the atomic write of the index JSON,
        the previously saved index must still be loadable."""
        store = IndexStore(base_path=str(tmp_path))
        _save_simple_index(store, "local", "proj", sym_name="original")

        # Verify the first index is loadable
        idx = store.load_index("local", "proj")
        assert idx is not None
        assert len(idx.symbols) == 1
        assert idx.symbols[0]["name"] == "original"

        # Now simulate a crash during the second save: patch Path.replace
        # to raise OSError when renaming the .json.gz.tmp -> .json.gz
        original_replace = Path.replace

        def failing_replace(self_path, target):
            if ".json.gz.tmp" in str(self_path):
                raise OSError("Simulated disk failure during rename")
            return original_replace(self_path, target)

        src2 = "def updated():\n    return 99\n"
        symbols2 = [_make_symbol("updated", src2)]

        with patch.object(Path, "replace", failing_replace):
            with pytest.raises(OSError, match="Simulated disk failure"):
                store.save_index(
                    owner="local",
                    name="proj",
                    source_files=["test.py"],
                    symbols=symbols2,
                    raw_files={"test.py": src2},
                    languages={"python": 1},
                )

        # The original index must still be intact
        store2 = IndexStore(base_path=str(tmp_path))
        idx2 = store2.load_index("local", "proj")
        assert idx2 is not None
        assert len(idx2.symbols) == 1
        assert idx2.symbols[0]["name"] == "original"

    def test_old_index_survives_when_index_write_fails(self, tmp_path):
        """If the index JSON write fails (Phase 3), the old index must still load.

        With the corrected phase ordering (RC-007), content files are
        committed (renamed from .tmp) in Phase 2 BEFORE the index JSON
        is written in Phase 3.  So when the index write fails, content
        on disk has been updated but the old index metadata is preserved.
        The key safety property: the old index remains loadable.
        """
        store = IndexStore(base_path=str(tmp_path))
        _save_simple_index(store, "local", "proj", sym_name="original")

        # Verify first index loads
        idx = store.load_index("local", "proj")
        assert idx is not None
        assert idx.symbols[0]["name"] == "original"

        # Fail the second save during the index JSON write (Phase 3)
        original_replace = Path.replace

        def failing_replace(self_path, target):
            if ".json.gz.tmp" in str(self_path):
                raise OSError("Simulated write failure")
            return original_replace(self_path, target)

        src2 = "def updated():\n    return 99\n"
        symbols2 = [_make_symbol("updated", src2)]

        with patch.object(Path, "replace", failing_replace):
            with pytest.raises(OSError):
                store.save_index(
                    owner="local",
                    name="proj",
                    source_files=["test.py"],
                    symbols=symbols2,
                    raw_files={"test.py": src2},
                    languages={"python": 1},
                )

        # The old index metadata must still be intact
        store2 = IndexStore(base_path=str(tmp_path))
        idx2 = store2.load_index("local", "proj")
        assert idx2 is not None
        assert len(idx2.symbols) == 1
        assert idx2.symbols[0]["name"] == "original"


class TestTmpFileCleanup:
    """Verify .tmp files are cleaned up after failed writes."""

    def test_no_index_tmp_after_failed_write(self, tmp_path):
        """After a failed save_index, no .json.gz.tmp files should remain."""
        store = IndexStore(base_path=str(tmp_path))

        original_replace = Path.replace

        def failing_replace(self_path, target):
            if ".json.gz.tmp" in str(self_path):
                raise OSError("Simulated failure")
            return original_replace(self_path, target)

        src = "def foo():\n    return 42\n"
        symbols = [_make_symbol("foo", src)]

        with patch.object(Path, "replace", failing_replace):
            with pytest.raises(OSError):
                store.save_index(
                    owner="local",
                    name="proj",
                    source_files=["test.py"],
                    symbols=symbols,
                    raw_files={"test.py": src},
                    languages={"python": 1},
                )

        # _atomic_write cleans up its .tmp on failure
        tmp_files = list(tmp_path.glob("*.json.gz.tmp"))
        assert tmp_files == [], f"Leftover .tmp files: {tmp_files}"

    def test_no_content_tmp_after_failed_index_write(self, tmp_path):
        """Content .tmp files are already renamed (Phase 2) before index write (Phase 3) fails."""
        store = IndexStore(base_path=str(tmp_path))

        original_replace = Path.replace
        call_count = 0

        def failing_on_index_replace(self_path, target):
            nonlocal call_count
            if ".json.gz.tmp" in str(self_path):
                raise OSError("Simulated index write failure")
            # Content .tmp renames (Phase 2) succeed before the index
            # write (Phase 3) triggers this failure.
            return original_replace(self_path, target)

        src = "def foo():\n    return 42\n"
        symbols = [_make_symbol("foo", src)]

        with patch.object(Path, "replace", failing_on_index_replace):
            with pytest.raises(OSError):
                store.save_index(
                    owner="local",
                    name="proj",
                    source_files=["test.py"],
                    symbols=symbols,
                    raw_files={"test.py": src},
                    languages={"python": 1},
                )

        # Content .tmp files should be cleaned up by the finally block
        content_dir = tmp_path / "local__proj"
        if content_dir.exists():
            content_tmps = list(content_dir.rglob("*.tmp"))
            assert content_tmps == [], f"Leftover content .tmp files: {content_tmps}"


class TestAtomicWriteAtomicity:
    """Verify _atomic_write produces no partial content."""

    def test_atomic_write_creates_complete_file(self, tmp_path):
        """After _atomic_write succeeds, the file contains the full data."""
        store = IndexStore(base_path=str(tmp_path))
        target = tmp_path / "test_output.json.gz"
        data = b"complete binary payload with enough bytes to be meaningful"

        store._atomic_write(target, data)

        assert target.exists()
        assert target.read_bytes() == data

    def test_atomic_write_no_partial_on_write_failure(self, tmp_path):
        """If writing to the .tmp file fails, the final file must not exist."""
        store = IndexStore(base_path=str(tmp_path))
        target = tmp_path / "test_output.json.gz"

        # Simulate a write error by patching os.fdopen to raise
        original_fdopen = os.fdopen

        def failing_fdopen(fd, *args, **kwargs):
            os.close(fd)
            raise IOError("Simulated write failure")

        with patch("os.fdopen", failing_fdopen):
            with pytest.raises(IOError):
                store._atomic_write(target, b"some data")

        assert not target.exists(), "Final file should not exist after write failure"

        # .tmp should also not exist
        tmp_file = target.with_suffix(target.suffix + ".tmp")
        assert not tmp_file.exists(), ".tmp file should be cleaned up"

    def test_atomic_write_overwrites_existing_atomically(self, tmp_path):
        """An atomic write to an existing file replaces it completely."""
        store = IndexStore(base_path=str(tmp_path))
        target = tmp_path / "test_output.dat"

        store._atomic_write(target, b"version1")
        assert target.read_bytes() == b"version1"

        store._atomic_write(target, b"version2-longer-content")
        assert target.read_bytes() == b"version2-longer-content"

    def test_successful_save_produces_valid_gzip_index(self, tmp_path):
        """A successful save_index produces a valid gzip-compressed JSON index."""
        store = IndexStore(base_path=str(tmp_path))
        _save_simple_index(store, "local", "proj")

        index_path = tmp_path / "local__proj.json.gz"
        assert index_path.exists()

        # Verify it's valid gzip containing valid JSON
        with gzip.open(index_path, "rb") as f:
            data = json.loads(f.read().decode("utf-8"))

        assert data["owner"] == "local"
        assert data["name"] == "proj"
        assert len(data["symbols"]) == 1
