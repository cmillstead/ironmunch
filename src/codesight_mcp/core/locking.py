"""Small file-lock helpers for persistent local coordination."""

from __future__ import annotations

import os
import random
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

_LOCK_TIMEOUT_SECONDS: float = 30.0
_LOCK_RETRY_INTERVAL: float = 0.1

# Process-wide lock for umask manipulation.  os.umask() is process-global,
# so every call site that temporarily changes umask must hold this lock.
_UMASK_LOCK = threading.Lock()


def ensure_private_dir(path: str | Path) -> Path:
    """Create a directory and enforce owner-only permissions."""
    if not str(path).strip():
        raise OSError("empty path")
    target = Path(path)
    if target == Path("/") or target == target.parent:
        raise OSError("refusing to operate on filesystem root")
    if target.is_symlink():
        raise OSError("Refusing to use symlinked directory")
    with _UMASK_LOCK:
        old_umask = os.umask(0o077)
        try:
            target.mkdir(parents=True, exist_ok=True, mode=0o700)
        finally:
            os.umask(old_umask)
    if not target.is_dir():
        raise OSError("Path is not a directory")
    os.chmod(target, 0o700)
    return target


def atomic_write_nofollow(path: str | Path, data: str) -> None:
    """Atomically write text data without following symlinks at the temp path."""
    target = Path(path)
    tmp_path = target.with_suffix(target.suffix + ".tmp")
    fd = os.open(
        str(tmp_path),
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(data)
        try:
            tmp_path.replace(target)
        except OSError:
            tmp_path.unlink(missing_ok=True)
            tmp_path = None
            raise
    except Exception:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)
        raise


@contextmanager
def exclusive_file_lock(lock_path: str | Path) -> Iterator[None]:
    """Acquire an exclusive advisory lock for the lifetime of the context."""
    import fcntl

    path = Path(lock_path)
    ensure_private_dir(path.parent)
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
        attempt = 0
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except (OSError, BlockingIOError):
                if time.monotonic() >= deadline:
                    os.close(fd)
                    fd = -1
                    raise TimeoutError(
                        f"Could not acquire lock on {lock_path} "
                        f"within {_LOCK_TIMEOUT_SECONDS}s"
                    )
                attempt += 1
                base = min(0.05 * (1.5 ** min(attempt, 10)), 1.0)
                time.sleep(base + random.uniform(0, base * 0.5))
        yield
    finally:
        if fd >= 0:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
