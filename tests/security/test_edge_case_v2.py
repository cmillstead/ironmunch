"""Tests for Chunk 2 edge-case hardening (Tasks 7-16)."""

import os
import threading
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from codesight_mcp.core.locking import ensure_private_dir, _UMASK_LOCK
from codesight_mcp.storage.index_store import IndexStore, _makedirs_0o700
from codesight_mcp.parser.symbols import Symbol
from codesight_mcp.security import sanitize_signature_for_api
from codesight_mcp.core.validation import ValidationError


# ---------------------------------------------------------------------------
# Task 7: ensure_private_dir uses shared _UMASK_LOCK
# ---------------------------------------------------------------------------

class TestEnsurePrivateDirUmaskLock:
    """Task 7: ensure_private_dir must hold _UMASK_LOCK around umask manipulation."""

    def test_ensure_private_dir_uses_umask_lock(self, tmp_path):
        """Verify that ensure_private_dir acquires _UMASK_LOCK."""
        lock_acquired = threading.Event()
        lock_blocked = threading.Event()

        def hold_lock():
            with _UMASK_LOCK:
                lock_acquired.set()
                lock_blocked.wait(timeout=5)

        t = threading.Thread(target=hold_lock)
        t.start()
        lock_acquired.wait(timeout=5)

        # Now _UMASK_LOCK is held by the other thread.
        # ensure_private_dir should block until it can acquire the lock.
        result_ready = threading.Event()
        result = {}

        def try_ensure():
            try:
                ensure_private_dir(tmp_path / "subdir")
                result["ok"] = True
            except Exception as e:
                result["error"] = e
            result_ready.set()

        t2 = threading.Thread(target=try_ensure)
        t2.start()

        # Give t2 a moment to block
        assert not result_ready.wait(timeout=0.3), (
            "ensure_private_dir did not block on _UMASK_LOCK"
        )

        # Release the lock
        lock_blocked.set()
        t.join(timeout=5)
        result_ready.wait(timeout=5)
        t2.join(timeout=5)

        assert result.get("ok"), f"ensure_private_dir failed: {result}"

    def test_makedirs_and_ensure_share_same_lock(self):
        """_makedirs_0o700 and ensure_private_dir use the same _UMASK_LOCK."""
        from codesight_mcp.storage.index_store import _UMASK_LOCK as store_lock
        from codesight_mcp.core.locking import _UMASK_LOCK as locking_lock
        assert store_lock is locking_lock


# ---------------------------------------------------------------------------
# Task 8: load_index stat-before-open TOCTOU
# ---------------------------------------------------------------------------

class TestLoadIndexFstat:
    """Task 8: load_index must use fstat after O_NOFOLLOW open, not stat before."""

    def test_load_index_uses_fstat_not_stat(self, tmp_path):
        """Verify that load_index uses os.fstat after opening the file."""
        store = IndexStore(base_path=str(tmp_path))
        store.save_index(
            owner="test", name="repo",
            source_files=["main.py"],
            symbols=[],
            raw_files={"main.py": "x = 1"},
            languages={"python": 1},
        )

        fstat_called = []
        original_fstat = os.fstat

        def tracking_fstat(fd):
            fstat_called.append(fd)
            return original_fstat(fd)

        with patch("codesight_mcp.storage.index_store.os.fstat", side_effect=tracking_fstat):
            loaded = store.load_index("test", "repo")

        assert loaded is not None
        assert len(fstat_called) > 0, "os.fstat was not called during load_index"


# ---------------------------------------------------------------------------
# Task 9: truncation-before-redaction in sanitize_signature_for_api
# ---------------------------------------------------------------------------

class TestSanitizeTruncationOrder:
    """Task 9: Truncation must happen AFTER redaction to avoid splitting secrets."""

    def test_secret_at_truncation_boundary_still_redacted(self):
        """A secret starting near position 9995 must still be fully redacted."""
        # Build a 10005-char string with a secret at position 9995
        padding = "A" * 9995
        secret = "sk-" + "x" * 30  # 33 chars total, extends past 10000
        sig = padding + secret
        assert len(sig) > 10000

        result = sanitize_signature_for_api(sig)
        # The secret must be fully redacted, not partially truncated
        assert "sk-" not in result, (
            f"Secret at truncation boundary was not fully redacted: ...{result[-50:]!r}"
        )


# ---------------------------------------------------------------------------
# Task 10: _atomic_write predictable tmp path
# ---------------------------------------------------------------------------

class TestAtomicWriteTmpPath:
    """Task 10: _atomic_write must use PID/thread-unique tmp filename."""

    def test_atomic_write_uses_unique_tmp_name(self, tmp_path):
        """Verify _atomic_write uses PID and thread ident in tmp filename."""
        store = IndexStore(base_path=str(tmp_path))
        final_path = tmp_path / "test_file.json.gz"

        # Track the tmp path used by patching os.open
        captured_paths = []
        original_open = os.open

        def tracking_open(path, flags, *args, **kwargs):
            if ".tmp" in str(path):
                captured_paths.append(str(path))
            return original_open(path, flags, *args, **kwargs)

        with patch("codesight_mcp.storage.index_store.os.open", side_effect=tracking_open):
            store._atomic_write(final_path, b"test data")

        assert len(captured_paths) > 0, "_atomic_write did not create a .tmp file"
        tmp_name = captured_paths[0]
        assert str(os.getpid()) in tmp_name, (
            f"PID not found in tmp filename: {tmp_name}"
        )
        assert str(threading.get_ident()) in tmp_name, (
            f"Thread ident not found in tmp filename: {tmp_name}"
        )


# ---------------------------------------------------------------------------
# Task 11: _symbol_to_dict not sanitizing at save time
# ---------------------------------------------------------------------------

class TestSymbolToDictSanitization:
    """Task 11: _symbol_to_dict must sanitize signature/docstring/summary."""

    def test_symbol_to_dict_sanitizes_signature(self, tmp_path):
        """A Symbol with a secret in its signature must have it redacted on save."""
        store = IndexStore(base_path=str(tmp_path))
        # Use string concatenation to avoid push protection
        secret = "sk-" + "abc123" * 5
        sym = Symbol(
            id="test.py::connect#function",
            file="test.py",
            name="connect",
            qualified_name="connect",
            kind="function",
            language="python",
            signature=f"def connect(key={secret}):",
            docstring=f"Uses key {secret} for auth.",
            summary=f"Connects with {secret}.",
            byte_offset=0,
            byte_length=50,
        )
        result = store._symbol_to_dict(sym)
        assert secret not in result["signature"], (
            f"Secret leaked in _symbol_to_dict signature: {result['signature']!r}"
        )
        assert secret not in result["docstring"], (
            f"Secret leaked in _symbol_to_dict docstring: {result['docstring']!r}"
        )
        assert secret not in result["summary"], (
            f"Secret leaked in _symbol_to_dict summary: {result['summary']!r}"
        )


# ---------------------------------------------------------------------------
# Task 12: load_index not sanitizing name/id/file fields
# ---------------------------------------------------------------------------

class TestLoadIndexSanitizesNameAndFile:
    """Task 12: load_index must sanitize name and file fields in symbols."""

    def test_load_index_sanitizes_name_field(self, tmp_path):
        """A symbol with a secret in its name must be sanitized on load."""
        store = IndexStore(base_path=str(tmp_path))
        store.save_index(
            owner="test", name="repo",
            source_files=["main.py"],
            symbols=[
                Symbol(
                    id="main.py::foo#function",
                    file="main.py",
                    name="foo",
                    qualified_name="foo",
                    kind="function",
                    language="python",
                    signature="def foo():",
                    byte_offset=0, byte_length=10,
                )
            ],
            raw_files={"main.py": "def foo(): pass"},
            languages={"python": 1},
        )

        # Tamper with the index to inject a secret in the name field
        import gzip, json
        index_path = tmp_path / "test__repo.json.gz"
        raw = gzip.decompress(index_path.read_bytes())
        data = json.loads(raw.decode("utf-8"))
        secret = "sk-" + "z" * 30
        data["symbols"][0]["name"] = f"func_{secret}"
        data["symbols"][0]["file"] = f"src/{secret}/main.py"
        compressed = gzip.compress(json.dumps(data).encode("utf-8"))
        index_path.write_bytes(compressed)

        loaded = store.load_index("test", "repo")
        assert loaded is not None
        sym = loaded.symbols[0]
        assert secret not in sym.get("name", ""), (
            f"Secret leaked in name field: {sym['name']!r}"
        )
        assert secret not in sym.get("file", ""), (
            f"Secret leaked in file field: {sym['file']!r}"
        )


# ---------------------------------------------------------------------------
# Task 13: delete_index following symlinks in rmtree
# ---------------------------------------------------------------------------

class TestDeleteIndexSymlinks:
    """Task 13: delete_index must not follow symlinks inside content directory."""

    def test_delete_index_skips_symlinks(self, tmp_path):
        """Symlinks inside the content directory must not be followed during delete."""
        import sys
        if sys.platform == "win32":
            pytest.skip("Symlinks unreliable on Windows")

        store = IndexStore(base_path=str(tmp_path))
        store.save_index(
            owner="test", name="repo",
            source_files=["main.py"],
            symbols=[],
            raw_files={"main.py": "x = 1"},
            languages={"python": 1},
        )

        # Create an outside file and plant a symlink inside the content dir
        outside_file = tmp_path / "outside_precious.txt"
        outside_file.write_text("precious data")

        content_dir = tmp_path / "test__repo"
        symlink = content_dir / "evil_link"
        symlink.symlink_to(outside_file)

        store.delete_index("test", "repo")

        # The outside file must NOT be deleted
        assert outside_file.exists(), (
            "delete_index followed symlink and deleted outside file"
        )


# ---------------------------------------------------------------------------
# Task 14: double-encoded traversal bypass in fetch_file_content
# ---------------------------------------------------------------------------

class TestDoubleEncodedTraversal:
    """Task 14: Double-encoded traversal (%252e%252e) must be rejected."""

    def test_fully_unquote_double_encoded(self):
        """_fully_unquote must decode double-encoded '..' to literal '..'."""
        from codesight_mcp.discovery import _fully_unquote
        # %252e -> first unquote -> %2e -> second unquote -> .
        result = _fully_unquote("%252e%252e/etc/passwd")
        assert ".." in result

    @pytest.mark.asyncio
    async def test_double_encoded_traversal_rejected(self):
        """fetch_file_content must reject double-encoded '..' sequences."""
        from codesight_mcp.discovery import fetch_file_content
        # %252e%252e -> first unquote -> %2e%2e -> second unquote -> ..
        path = "%252e%252e/etc/passwd"
        with pytest.raises(ValueError, match="traversal"):
            await fetch_file_content("owner", "repo", path, token=None)

    @pytest.mark.asyncio
    async def test_triple_encoded_traversal_rejected(self):
        """Triple-encoded traversal must also be rejected."""
        from codesight_mcp.discovery import fetch_file_content
        # %25252e%25252e -> %252e%252e -> %2e%2e -> ..
        path = "%25252e%25252e/etc/passwd"
        with pytest.raises(ValueError, match="traversal"):
            await fetch_file_content("owner", "repo", path, token=None)


# ---------------------------------------------------------------------------
# Task 15: list_repos trusted=True contradiction
# ---------------------------------------------------------------------------

class TestListReposTrustedFalse:
    """Task 15: list_repos must use trusted=False since repo names are disk-derived."""

    def test_list_repos_meta_uses_untrusted(self, tmp_path):
        """list_repos _meta must have contentTrust=untrusted."""
        from codesight_mcp.tools.list_repos import list_repos
        store = IndexStore(base_path=str(tmp_path))
        store.save_index(
            owner="test", name="repo",
            source_files=["main.py"],
            symbols=[],
            raw_files={"main.py": "x = 1"},
            languages={"python": 1},
        )
        result = list_repos(storage_path=str(tmp_path))
        assert result["_meta"]["contentTrust"] == "untrusted", (
            f"Expected untrusted, got: {result['_meta']['contentTrust']!r}"
        )


# ---------------------------------------------------------------------------
# Task 16: Remove static <<<SPLIT>>> fallback in batch summarizer
# ---------------------------------------------------------------------------

class TestSplitPromptNoStaticFallback:
    """Task 16: _split_prompt must not split on static <<<SPLIT>>> without nonce."""

    def test_static_split_marker_not_honored(self):
        """A prompt with only static <<<SPLIT>>> must not be split."""
        from codesight_mcp.summarizer.batch_summarize import BatchSummarizer
        prompt = "System instructions\n<<<SPLIT>>>\nUser data here"
        system, user = BatchSummarizer._split_prompt(prompt, nonce="somerealnonce")
        # Without a matching nonce marker, the static fallback should NOT split.
        # The entire prompt should end up as user (system="").
        assert system == "", (
            f"Static <<<SPLIT>>> was honored as fallback, system={system!r}"
        )
        assert prompt == user or "<<<SPLIT>>>" in user, (
            f"Expected entire prompt as user part, got user={user!r}"
        )

    def test_nonce_split_marker_still_works(self):
        """A prompt with the correct nonce-based marker must still be split."""
        from codesight_mcp.summarizer.batch_summarize import BatchSummarizer
        nonce = "abc123def456"
        prompt = f"System part\n<<<SPLIT_{nonce}>>>\nUser part"
        system, user = BatchSummarizer._split_prompt(prompt, nonce=nonce)
        assert system == "System part"
        assert user == "User part"


def test_validate_storage_path_uses_lstat(monkeypatch):
    """_validate_storage_path should use lstat, not stat (which follows symlinks)."""
    import inspect
    from codesight_mcp.server import _validate_storage_path

    source = inspect.getsource(_validate_storage_path)
    assert "resolved.stat()" not in source, "should use lstat() not stat()"
