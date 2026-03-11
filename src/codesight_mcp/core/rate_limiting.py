"""Persistent file-backed sliding-window rate limiting."""

import errno
import json
import logging
import os
import secrets
import tempfile
import time
from pathlib import Path

from .locking import atomic_write_nofollow, ensure_private_dir, exclusive_file_lock
from .limits import MAX_INDEX_SIZE

_MAX_CALLS_PER_MINUTE: int = 60
_MAX_GLOBAL_CALLS_PER_MINUTE: int = 300
_RATE_WINDOW_SECONDS: int = 60
_MAX_TIMESTAMPS_PER_TOOL: int = _MAX_CALLS_PER_MINUTE * 2
_MAX_GLOBAL_TIMESTAMPS: int = _MAX_GLOBAL_CALLS_PER_MINUTE * 2


def _rate_limit_state_dir(storage_path: str | None) -> Path:
    """Directory where persistent rate-limit state lives."""
    if storage_path is not None:
        return ensure_private_dir(storage_path)
    default_dir = Path.home() / ".code-index"
    try:
        ensure_private_dir(default_dir)
        probe = default_dir / ".rate_limit_probe"
        atomic_write_nofollow(probe, "")
        probe.unlink(missing_ok=True)
        return default_dir
    except OSError:
        uid = getattr(os, "getuid", lambda: None)()
        suffix = str(uid) if uid is not None else os.environ.get("USER", "unknown")
        # ADV-INFO-1: Catch PermissionError from pre-created dir (Linux /tmp),
        # retry with random suffix to avoid predictable name DoS.
        try:
            return ensure_private_dir(Path(tempfile.gettempdir()) / f"codesight-mcp-rate-limits-{suffix}")
        except PermissionError:
            try:
                rand = secrets.token_hex(8)
                return ensure_private_dir(Path(tempfile.gettempdir()) / f"codesight-mcp-rate-limits-{suffix}-{rand}")
            except PermissionError:
                return None


def _rate_limit(tool_name: str, storage_path: str | None) -> bool:
    """Check a persistent rate limit bucket. Returns True if allowed."""
    state_dir = _rate_limit_state_dir(storage_path)
    if state_dir is None:
        logging.getLogger(__name__).warning("Rate limiting disabled: unable to create state directory")
        return True  # Allow the call if we can't set up rate limiting
    lock_path = state_dir / ".rate_limits.lock"
    state_path = state_dir / ".rate_limits.json"
    now = time.time()

    with exclusive_file_lock(lock_path):
        # ADV-LOW-3: Use O_NOFOLLOW to prevent symlink-based DoS
        # (e.g., symlink to /dev/zero would block forever on read_text).
        try:
            fd = os.open(str(state_path), os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                data = {}  # symlink — reject silently
            elif exc.errno == errno.ENOENT:
                data = {}  # file doesn't exist yet
            else:
                data = {}
        else:
            try:
                with os.fdopen(fd, "r", encoding="utf-8") as fh:
                    raw = fh.read(MAX_INDEX_SIZE + 1)
                    if len(raw) > MAX_INDEX_SIZE:
                        data = {}
                    else:
                        data = json.loads(raw)
            except (json.JSONDecodeError, OSError, ValueError):
                data = {}
        if not isinstance(data, dict):
            data = {}

        global_timestamps = [
            float(t)
            for t in data.get("global", [])
            if isinstance(t, (int, float)) and now - float(t) < _RATE_WINDOW_SECONDS and float(t) <= now + 5
        ]
        # Cap global timestamps to prevent memory/CPU spike from huge arrays
        if len(global_timestamps) > _MAX_GLOBAL_TIMESTAMPS:
            global_timestamps = global_timestamps[-_MAX_GLOBAL_TIMESTAMPS:]
        tool_map = data.get("tools", {})
        if not isinstance(tool_map, dict):
            tool_map = {}
        # Cap each tool's timestamps on load
        for tname in list(tool_map.keys()):
            if not isinstance(tool_map.get(tname), list):
                tool_map[tname] = []
                continue
            entries = [
                float(t)
                for t in tool_map[tname]
                if isinstance(t, (int, float)) and now - float(t) < _RATE_WINDOW_SECONDS and float(t) <= now + 5
            ]
            if entries:
                tool_map[tname] = entries[-_MAX_TIMESTAMPS_PER_TOOL:]
            else:
                # Prune stale tool entries with no valid timestamps
                del tool_map[tname]
        tool_timestamps = tool_map.get(tool_name, [])

        if len(global_timestamps) >= _MAX_GLOBAL_CALLS_PER_MINUTE:
            return False
        if len(tool_timestamps) >= _MAX_CALLS_PER_MINUTE:
            return False

        global_timestamps.append(now)
        tool_timestamps.append(now)
        tool_map[tool_name] = tool_timestamps
        state = {"global": global_timestamps, "tools": tool_map}
        try:
            atomic_write_nofollow(state_path, json.dumps(state))
        except OSError as exc:
            logging.getLogger(__name__).warning("Failed to persist rate limit state: %s", exc)
        return True
