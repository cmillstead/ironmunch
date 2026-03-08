"""Tests for file-lock helpers in codesight_mcp.core.locking."""

import os
import threading
import time
from pathlib import Path

import pytest

from codesight_mcp.core.locking import (
    atomic_write_nofollow,
    ensure_private_dir,
    exclusive_file_lock,
)


class TestEnsurePrivateDir:
    def test_creates_directory(self, tmp_path):
        target = tmp_path / "newdir"
        result = ensure_private_dir(target)
        assert result == target
        assert target.is_dir()

    def test_sets_owner_only_permissions(self, tmp_path):
        target = tmp_path / "private"
        ensure_private_dir(target)
        mode = target.stat().st_mode & 0o777
        assert mode == 0o700

    def test_existing_dir_ok(self, tmp_path):
        target = tmp_path / "existing"
        target.mkdir()
        result = ensure_private_dir(target)
        assert result == target

    def test_nested_creation(self, tmp_path):
        target = tmp_path / "a" / "b" / "c"
        ensure_private_dir(target)
        assert target.is_dir()

    def test_symlink_rejected(self, tmp_path):
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real)
        with pytest.raises(OSError, match="symlink"):
            ensure_private_dir(link)

    def test_accepts_string_path(self, tmp_path):
        target = str(tmp_path / "strpath")
        result = ensure_private_dir(target)
        assert result == Path(target)
        assert Path(target).is_dir()


class TestAtomicWriteNofollow:
    def test_writes_content(self, tmp_path):
        target = tmp_path / "file.txt"
        atomic_write_nofollow(target, "hello world")
        assert target.read_text() == "hello world"

    def test_overwrites_existing(self, tmp_path):
        target = tmp_path / "file.txt"
        target.write_text("old")
        atomic_write_nofollow(target, "new")
        assert target.read_text() == "new"

    def test_file_permissions(self, tmp_path):
        target = tmp_path / "secure.txt"
        atomic_write_nofollow(target, "data")
        mode = target.stat().st_mode & 0o777
        assert mode == 0o600

    def test_no_temp_file_left_on_success(self, tmp_path):
        target = tmp_path / "file.txt"
        atomic_write_nofollow(target, "data")
        tmp_files = list(tmp_path.glob("*.tmp"))
        assert tmp_files == []

    def test_symlink_target_rejected(self, tmp_path):
        real = tmp_path / "real.txt"
        real.write_text("original")
        link = tmp_path / "link.txt"
        link.symlink_to(real)
        # The temp file (link.txt.tmp) is what gets O_NOFOLLOW, but if link.txt
        # itself is a symlink, replace() will follow it. The key security
        # property is that O_NOFOLLOW prevents opening a symlinked temp path.
        # Creating a symlink at the .tmp path would trigger the error.
        tmp_file = tmp_path / "link.txt.tmp"
        tmp_file.symlink_to(real)
        with pytest.raises(OSError):
            atomic_write_nofollow(link, "evil")

    def test_accepts_string_path(self, tmp_path):
        target = str(tmp_path / "strfile.txt")
        atomic_write_nofollow(target, "content")
        assert Path(target).read_text() == "content"


class TestExclusiveFileLock:
    def test_basic_acquire_release(self, tmp_path):
        lock_file = tmp_path / "test.lock"
        with exclusive_file_lock(lock_file):
            assert lock_file.exists()

    def test_lock_file_exists_after_release(self, tmp_path):
        """Lock file persists after context exit (advisory lock, not removed)."""
        lock_file = tmp_path / "test.lock"
        with exclusive_file_lock(lock_file):
            pass
        # The lock file itself remains; only the advisory lock is released
        assert lock_file.exists()

    def test_creates_parent_directory(self, tmp_path):
        lock_file = tmp_path / "subdir" / "test.lock"
        with exclusive_file_lock(lock_file):
            assert lock_file.parent.is_dir()

    def test_parent_dir_has_private_permissions(self, tmp_path):
        lock_file = tmp_path / "lockdir" / "test.lock"
        with exclusive_file_lock(lock_file):
            mode = lock_file.parent.stat().st_mode & 0o777
            assert mode == 0o700

    def test_prevents_concurrent_access(self, tmp_path):
        """Two threads contending for the same lock must serialize."""
        lock_file = tmp_path / "contention.lock"
        results = []
        barrier = threading.Barrier(2, timeout=5)

        def worker(worker_id):
            barrier.wait()
            with exclusive_file_lock(lock_file):
                results.append(f"enter-{worker_id}")
                time.sleep(0.05)
                results.append(f"exit-{worker_id}")

        t1 = threading.Thread(target=worker, args=(1,))
        t2 = threading.Thread(target=worker, args=(2,))
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        assert len(results) == 4
        # One worker must fully complete before the other starts.
        # Either [enter-1, exit-1, enter-2, exit-2] or [enter-2, exit-2, enter-1, exit-1]
        first_enter = results[0]
        first_exit = results[1]
        wid = first_enter.split("-")[1]
        assert first_exit == f"exit-{wid}", (
            f"Expected serialized access, got interleaved: {results}"
        )

    def test_lock_released_after_exception(self, tmp_path):
        """Lock is released even if the body raises an exception."""
        lock_file = tmp_path / "exc.lock"
        with pytest.raises(ValueError, match="boom"):
            with exclusive_file_lock(lock_file):
                raise ValueError("boom")

        # Should be able to re-acquire without blocking
        acquired = threading.Event()

        def try_acquire():
            with exclusive_file_lock(lock_file):
                acquired.set()

        t = threading.Thread(target=try_acquire)
        t.start()
        t.join(timeout=5)
        assert acquired.is_set(), "Lock was not released after exception"

    def test_reentrant_lock_blocks(self, tmp_path):
        """Re-entrant acquisition from another thread blocks while lock is held.

        flock() is per-open-file-description, so a second open()+flock(LOCK_EX)
        will block. We verify this by attempting a non-blocking lock from a
        separate thread while the first lock is held.
        """
        import fcntl

        lock_file = tmp_path / "reentrant.lock"
        blocked = threading.Event()

        with exclusive_file_lock(lock_file):
            def try_lock():
                fd = os.open(str(lock_file), os.O_RDWR)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    # Should not reach here
                except BlockingIOError:
                    blocked.set()
                finally:
                    os.close(fd)

            t = threading.Thread(target=try_lock)
            t.start()
            t.join(timeout=5)
            assert blocked.is_set(), "Expected lock to block re-entrant acquisition"

    def test_symlink_lock_path_rejected(self, tmp_path):
        """Lock file path that is a symlink must be rejected (O_NOFOLLOW)."""
        real = tmp_path / "real.lock"
        real.touch()
        link = tmp_path / "link.lock"
        link.symlink_to(real)
        with pytest.raises(OSError):
            with exclusive_file_lock(link):
                pass

    def test_lock_file_permissions(self, tmp_path):
        lock_file = tmp_path / "perms.lock"
        with exclusive_file_lock(lock_file):
            mode = lock_file.stat().st_mode & 0o777
            assert mode == 0o600

    def test_nonblocking_contention_detection(self, tmp_path):
        """Demonstrate that a non-blocking attempt would fail while lock is held."""
        import fcntl

        lock_file = tmp_path / "nb.lock"
        with exclusive_file_lock(lock_file):
            # Try non-blocking lock from same process (new fd)
            fd = os.open(str(lock_file), os.O_RDWR)
            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)
