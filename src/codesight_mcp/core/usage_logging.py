"""Usage logging for MCP tool invocations."""

from __future__ import annotations

import json
import os
import time as _time
import threading
from dataclasses import dataclass, field
from pathlib import Path

from .locking import ensure_private_dir

_MAX_LOG_BYTES = 50 * 1024 * 1024


@dataclass
class UsageRecord:
    """A single tool invocation record."""

    tool_name: str
    timestamp: float
    success: bool
    error_message: str | None
    response_time_ms: int
    argument_keys: list[str] = field(default_factory=list)
    session_id: str = field(default="")

    def __post_init__(self) -> None:
        self.response_time_ms = (self.response_time_ms + 5) // 10 * 10

    def to_dict(self) -> dict:
        return {
            "tool_name": self.tool_name,
            "timestamp": self.timestamp,
            "success": self.success,
            "error_message": self.error_message,
            "response_time_ms": self.response_time_ms,
            "argument_keys": list(self.argument_keys),
            "session_id": self.session_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> UsageRecord:
        return cls(
            tool_name=data.get("tool_name", ""),
            timestamp=data.get("timestamp", 0.0),
            success=data.get("success", False),
            error_message=data.get("error_message"),
            response_time_ms=data.get("response_time_ms", 0),
            argument_keys=data.get("argument_keys", []),
            session_id=data.get("session_id", ""),
        )


class UsageLogger:
    """In-memory usage logger with optional eviction."""

    def __init__(
        self,
        max_memory: int = 10_000,
        log_path: str | None = None,
        enabled: bool = True,
    ) -> None:
        self._records: list[UsageRecord] = []
        self._lock = threading.Lock()
        self._max_memory = max(1, max_memory)
        self._log_path = Path(log_path) if log_path else None
        self._enabled = enabled
        self._session_id = f"{os.getpid()}-{_time.time():.0f}"
        self._history_cache: list[UsageRecord] | None = None

    @classmethod
    def from_env(cls) -> UsageLogger:
        """Create a UsageLogger configured from environment variables."""
        log_path = os.environ.get("CODESIGHT_USAGE_LOG") or None
        enabled = os.environ.get("CODESIGHT_USAGE_ENABLED", "1") != "0"
        max_memory = 10_000
        raw = os.environ.get("CODESIGHT_USAGE_MAX_MEMORY")
        if raw:
            try:
                max_memory = int(raw)
            except ValueError:
                pass
        return cls(max_memory=max_memory, log_path=log_path, enabled=enabled)

    def record(self, rec: UsageRecord) -> None:
        """Append a record. Silently catches all exceptions."""
        if not self._enabled:
            return
        try:
            with self._lock:
                rec.session_id = self._session_id
                self._records.append(rec)
                if len(self._records) > self._max_memory:
                    evict_count = max(1, int(self._max_memory * 0.2))
                    self._records = self._records[evict_count:]
        except Exception:
            pass
        try:
            self._write_to_file(rec)
        except Exception:
            pass

    def _write_to_file(self, rec: UsageRecord) -> None:
        """Write a record as JSONL to the log file."""
        if self._log_path is None:
            return
        self._history_cache = None
        path = self._log_path
        ensure_private_dir(path.parent)
        # Rotate if file exceeds size limit
        if path.exists() and not path.is_symlink():
            try:
                if path.stat().st_size > _MAX_LOG_BYTES:
                    rotated = path.with_name(path.name + ".1")
                    if rotated.exists():
                        rotated.unlink()
                    path.rename(rotated)
            except OSError:
                pass
        data_bytes = (json.dumps(rec.to_dict()) + "\n").encode()
        fd = os.open(
            str(path),
            os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
            0o600,
        )
        try:
            os.write(fd, data_bytes)
        finally:
            os.close(fd)

    def _all_records(self) -> list[UsageRecord]:
        """Merge file history + in-memory records, deduplicating current session."""
        with self._lock:
            memory = list(self._records)
        if not self._log_path:
            return memory
        file_records = self.load_history()
        if not file_records:
            return memory
        if not memory:
            return list(file_records)
        # Deduplicate: file records from before current session
        earliest_memory_ts = memory[0].timestamp
        history = [r for r in file_records if r.timestamp < earliest_memory_ts]
        return history + memory

    def get_records(self, tool_name: str | None = None) -> list[UsageRecord]:
        """Return merged file + memory records, optionally filtered."""
        records = self._all_records()
        if tool_name is not None:
            return [r for r in records if r.tool_name == tool_name]
        return records

    def load_history(self) -> list[UsageRecord]:
        """Read all records from the JSONL log file.

        Uses O_NOFOLLOW for symlink safety. Caches until next write.
        """
        if self._history_cache is not None:
            return self._history_cache
        if self._log_path is None or not self._log_path.exists():
            self._history_cache = []
            return self._history_cache
        try:
            fd = os.open(str(self._log_path), os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            self._history_cache = []
            return self._history_cache
        try:
            raw = b""
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                raw += chunk
        except OSError:
            self._history_cache = []
            return self._history_cache
        finally:
            os.close(fd)
        records: list[UsageRecord] = []
        for line in raw.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                records.append(UsageRecord.from_dict(data))
            except (json.JSONDecodeError, TypeError, KeyError):
                continue
        self._history_cache = records
        return self._history_cache
