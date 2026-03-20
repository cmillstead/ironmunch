"""Tests for UsageRecord and UsageLogger."""

import json
import os
import threading
import time

import pytest

from codesight_mcp.core.usage_logging import UsageLogger, UsageRecord


# ---------------------------------------------------------------------------
# TestUsageRecord
# ---------------------------------------------------------------------------

class TestUsageRecord:
    def test_create_success_record(self):
        rec = UsageRecord(
            tool_name="index_repo",
            timestamp=1000.0,
            success=True,
            error_message=None,
            response_time_ms=150,
            argument_keys=["repo", "branch"],
        )
        assert rec.tool_name == "index_repo"
        assert rec.timestamp == 1000.0
        assert rec.success is True
        assert rec.error_message is None
        assert rec.response_time_ms == 150
        assert rec.argument_keys == ["repo", "branch"]

    def test_create_error_record(self):
        rec = UsageRecord(
            tool_name="get_symbol",
            timestamp=2000.0,
            success=False,
            error_message="Symbol not found",
            response_time_ms=30,
            argument_keys=["symbol_id"],
        )
        assert rec.success is False
        assert rec.error_message == "Symbol not found"

    def test_response_time_rounded_to_10ms_buckets(self):
        rec = UsageRecord(
            tool_name="search_text",
            timestamp=1000.0,
            success=True,
            error_message=None,
            response_time_ms=127,
            argument_keys=[],
        )
        assert rec.response_time_ms == 130

    def test_response_time_rounding_edge_cases(self):
        cases = [(0, 0), (5, 10), (10, 10), (15, 20)]
        for raw, expected in cases:
            rec = UsageRecord(
                tool_name="t",
                timestamp=0.0,
                success=True,
                error_message=None,
                response_time_ms=raw,
                argument_keys=[],
            )
            assert rec.response_time_ms == expected, f"{raw} should round to {expected}"

    def test_to_dict(self):
        rec = UsageRecord(
            tool_name="index_repo",
            timestamp=1000.0,
            success=True,
            error_message=None,
            response_time_ms=130,
            argument_keys=["repo"],
        )
        d = rec.to_dict()
        assert d == {
            "tool_name": "index_repo",
            "timestamp": 1000.0,
            "success": True,
            "error_message": None,
            "response_time_ms": 130,
            "argument_keys": ["repo"],
            "session_id": "",
        }

    def test_from_dict(self):
        original = UsageRecord(
            tool_name="get_callers",
            timestamp=5000.0,
            success=False,
            error_message="timeout",
            response_time_ms=250,
            argument_keys=["symbol_id"],
        )
        d = original.to_dict()
        restored = UsageRecord.from_dict(d)
        assert restored == original

    def test_session_id_defaults_to_empty_string(self):
        rec = UsageRecord(
            tool_name="t",
            timestamp=0.0,
            success=True,
            error_message=None,
            response_time_ms=10,
        )
        assert rec.session_id == ""

    def test_session_id_in_to_dict(self):
        rec = UsageRecord(
            tool_name="t",
            timestamp=0.0,
            success=True,
            error_message=None,
            response_time_ms=10,
            session_id="123-1000",
        )
        d = rec.to_dict()
        assert d["session_id"] == "123-1000"

    def test_session_id_roundtrip_via_from_dict(self):
        rec = UsageRecord(
            tool_name="t",
            timestamp=0.0,
            success=True,
            error_message=None,
            response_time_ms=10,
            session_id="abc-999",
        )
        restored = UsageRecord.from_dict(rec.to_dict())
        assert restored.session_id == "abc-999"

    def test_from_dict_missing_session_id_defaults_empty(self):
        data = {
            "tool_name": "old_tool",
            "timestamp": 1.0,
            "success": True,
            "error_message": None,
            "response_time_ms": 50,
            "argument_keys": [],
        }
        rec = UsageRecord.from_dict(data)
        assert rec.session_id == ""


# ---------------------------------------------------------------------------
# TestUsageLoggerMemory
# ---------------------------------------------------------------------------

class TestUsageLoggerMemory:
    def _make_record(self, tool_name: str = "test_tool", success: bool = True,
                     response_time_ms: int = 100, timestamp: float | None = None) -> UsageRecord:
        return UsageRecord(
            tool_name=tool_name,
            timestamp=timestamp or time.time(),
            success=success,
            error_message=None if success else "err",
            response_time_ms=response_time_ms,
            argument_keys=[],
        )

    def test_record_and_get_records(self):
        logger = UsageLogger()
        rec = self._make_record()
        logger.record(rec)
        records = logger.get_records()
        assert len(records) == 1
        assert records[0] == rec

    def test_get_records_returns_copy(self):
        logger = UsageLogger()
        logger.record(self._make_record())
        r1 = logger.get_records()
        r2 = logger.get_records()
        assert r1 is not r2
        assert r1 == r2

    def test_eviction_at_max_memory(self):
        logger = UsageLogger(max_memory=10)
        records = []
        for i in range(11):
            rec = self._make_record(timestamp=float(i))
            records.append(rec)
            logger.record(rec)
        remaining = logger.get_records()
        # 20% of 10 = 2 evicted, so 9 remain
        assert len(remaining) == 9
        # Oldest 2 should be gone
        assert records[0] not in remaining
        assert records[1] not in remaining
        # The 11th record should be present
        assert records[10] in remaining

    def test_eviction_minimum_one(self):
        logger = UsageLogger(max_memory=1)
        logger.record(self._make_record(timestamp=1.0))
        logger.record(self._make_record(timestamp=2.0))
        remaining = logger.get_records()
        # max=1, 20% of 1 = 0.2, min 1 evicted → 1 remains
        assert len(remaining) == 1
        assert remaining[0].timestamp == 2.0

    def test_get_records_filtered_by_tool(self):
        logger = UsageLogger()
        logger.record(self._make_record(tool_name="alpha"))
        logger.record(self._make_record(tool_name="beta"))
        logger.record(self._make_record(tool_name="alpha"))
        assert len(logger.get_records(tool_name="alpha")) == 2
        assert len(logger.get_records(tool_name="beta")) == 1
        assert len(logger.get_records(tool_name="gamma")) == 0

    def test_get_stats_summary(self):
        logger = UsageLogger()
        logger.record(self._make_record(tool_name="a", success=True, response_time_ms=100))
        logger.record(self._make_record(tool_name="a", success=True, response_time_ms=200))
        logger.record(self._make_record(tool_name="a", success=False, response_time_ms=50))
        logger.record(self._make_record(tool_name="b", success=True, response_time_ms=300))

        stats = logger.get_stats()
        assert stats["a"]["total_calls"] == 3
        assert stats["a"]["success_count"] == 2
        assert stats["a"]["error_count"] == 1
        # avg of 100, 200, 50 = 116.67 → but these get rounded to 100, 200, 50 by bucket
        assert stats["a"]["avg_response_time_ms"] == pytest.approx(
            (100 + 200 + 50) / 3, abs=1
        )
        assert stats["b"]["total_calls"] == 1
        assert stats["b"]["success_count"] == 1
        assert stats["b"]["error_count"] == 0

    def test_thread_safety(self):
        logger = UsageLogger(max_memory=10_000)
        errors: list[Exception] = []

        def worker():
            try:
                for _ in range(100):
                    logger.record(self._make_record())
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(logger.get_records()) == 500

    def test_disabled_logger_no_op(self):
        logger = UsageLogger(enabled=False)
        logger.record(self._make_record())
        assert len(logger.get_records()) == 0

    def test_logger_stamps_session_id_on_records(self):
        logger = UsageLogger()
        rec = self._make_record()
        logger.record(rec)
        records = logger.get_records()
        assert records[0].session_id == logger._session_id

    def test_session_id_format_pid_dash_timestamp(self):
        logger = UsageLogger()
        parts = logger._session_id.split("-")
        assert len(parts) == 2
        int(parts[0])  # pid must be an integer
        int(parts[1])  # epoch seconds must be an integer


# ---------------------------------------------------------------------------
# TestUsageLoggerFile
# ---------------------------------------------------------------------------

class TestUsageLoggerFile:
    def _make_record(self, tool_name: str = "test_tool", success: bool = True,
                     response_time_ms: int = 100, timestamp: float | None = None) -> UsageRecord:
        return UsageRecord(
            tool_name=tool_name,
            timestamp=timestamp or time.time(),
            success=success,
            error_message=None if success else "err",
            response_time_ms=response_time_ms,
            argument_keys=[],
        )

    def test_writes_jsonl_to_disk(self, tmp_path):
        log_file = tmp_path / "usage.jsonl"
        logger = UsageLogger(log_path=str(log_file))
        logger.record(self._make_record(tool_name="alpha", timestamp=1.0))
        logger.record(self._make_record(tool_name="beta", timestamp=2.0))
        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 2
        first = json.loads(lines[0])
        assert first["tool_name"] == "alpha"
        second = json.loads(lines[1])
        assert second["tool_name"] == "beta"

    def test_file_created_with_0o600_permissions(self, tmp_path):
        log_file = tmp_path / "usage.jsonl"
        logger = UsageLogger(log_path=str(log_file))
        logger.record(self._make_record())
        assert log_file.stat().st_mode & 0o777 == 0o600

    def test_parent_dir_created_with_0o700(self, tmp_path):
        subdir = tmp_path / "logs" / "deep"
        log_file = subdir / "usage.jsonl"
        logger = UsageLogger(log_path=str(log_file))
        logger.record(self._make_record())
        assert subdir.stat().st_mode & 0o777 == 0o700

    def test_file_rotation_at_50mb(self, tmp_path):
        log_file = tmp_path / "usage.jsonl"
        # Pre-create a file larger than 50MB
        log_file.write_bytes(b"x" * (50 * 1024 * 1024 + 1))
        os.chmod(str(log_file), 0o600)
        logger = UsageLogger(log_path=str(log_file))
        logger.record(self._make_record(tool_name="after_rotate"))
        rotated = tmp_path / "usage.jsonl.1"
        assert rotated.exists()
        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 1
        assert json.loads(lines[0])["tool_name"] == "after_rotate"

    def test_symlink_log_path_rejected(self, tmp_path):
        real_file = tmp_path / "real.jsonl"
        real_file.write_text("")
        link = tmp_path / "link.jsonl"
        link.symlink_to(real_file)
        logger = UsageLogger(log_path=str(link))
        logger.record(self._make_record())
        # Real file should remain empty — symlink rejected by O_NOFOLLOW
        assert real_file.read_text() == ""

    def test_file_write_failure_does_not_break_memory_logging(self, tmp_path):
        # Use a directory as the log path — os.open will fail
        bad_path = tmp_path / "a_dir"
        bad_path.mkdir()
        logger = UsageLogger(log_path=str(bad_path))
        logger.record(self._make_record())
        assert len(logger.get_records()) == 1


# ---------------------------------------------------------------------------
# TestUsageLoggerConfig
# ---------------------------------------------------------------------------

_USAGE_ENV_VARS = ("CODESIGHT_USAGE_LOG", "CODESIGHT_USAGE_ENABLED", "CODESIGHT_USAGE_MAX_MEMORY")


class TestUsageLoggerConfig:
    """Tests for UsageLogger.from_env() using real os.environ."""

    def setup_method(self):
        """Save and clear usage env vars before each test."""
        self._saved = {k: os.environ.pop(k) for k in _USAGE_ENV_VARS if k in os.environ}

    def teardown_method(self):
        """Restore original env vars after each test."""
        for k in _USAGE_ENV_VARS:
            os.environ.pop(k, None)
        for k, v in self._saved.items():
            os.environ[k] = v

    def test_from_env_defaults(self):
        logger = UsageLogger.from_env()
        assert logger._enabled is True
        assert logger._max_memory == 10_000
        assert logger._log_path is None

    def test_from_env_custom_log_path(self, tmp_path):
        log_file = str(tmp_path / "usage.jsonl")
        os.environ["CODESIGHT_USAGE_LOG"] = log_file
        logger = UsageLogger.from_env()
        assert str(logger._log_path) == log_file

    def test_from_env_disabled(self):
        os.environ["CODESIGHT_USAGE_ENABLED"] = "0"
        logger = UsageLogger.from_env()
        assert logger._enabled is False

    def test_from_env_enabled_explicit(self):
        os.environ["CODESIGHT_USAGE_ENABLED"] = "1"
        logger = UsageLogger.from_env()
        assert logger._enabled is True

    def test_from_env_custom_max_memory(self):
        os.environ["CODESIGHT_USAGE_MAX_MEMORY"] = "500"
        logger = UsageLogger.from_env()
        assert logger._max_memory == 500

    def test_from_env_invalid_max_memory_uses_default(self):
        os.environ["CODESIGHT_USAGE_MAX_MEMORY"] = "notanumber"
        logger = UsageLogger.from_env()
        assert logger._max_memory == 10_000


# ---------------------------------------------------------------------------
# TestUsageLoggerLoadHistory
# ---------------------------------------------------------------------------

class TestUsageLoggerLoadHistory:
    def _make_record(self, tool_name: str = "test_tool", success: bool = True,
                     response_time_ms: int = 100, timestamp: float | None = None) -> UsageRecord:
        return UsageRecord(
            tool_name=tool_name,
            timestamp=timestamp or time.time(),
            success=success,
            error_message=None if success else "err",
            response_time_ms=response_time_ms,
            argument_keys=[],
        )

    def test_load_history_reads_jsonl_file(self, tmp_path):
        log_file = tmp_path / "usage.jsonl"
        logger = UsageLogger(log_path=str(log_file))
        logger.record(self._make_record(tool_name="alpha"))
        logger.record(self._make_record(tool_name="beta"))
        history = logger.load_history()
        assert len(history) == 2
        assert history[0].tool_name == "alpha"
        assert history[1].tool_name == "beta"

    def test_load_history_returns_empty_when_no_file(self):
        logger = UsageLogger(log_path=None)
        assert logger.load_history() == []

    def test_load_history_returns_empty_when_file_missing(self, tmp_path):
        logger = UsageLogger(log_path=str(tmp_path / "nonexistent.jsonl"))
        assert logger.load_history() == []

    def test_load_history_caches_result(self, tmp_path):
        log_file = tmp_path / "usage.jsonl"
        logger = UsageLogger(log_path=str(log_file))
        logger.record(self._make_record())
        h1 = logger.load_history()
        h2 = logger.load_history()
        assert h1 is h2

    def test_load_history_cache_invalidated_after_write(self, tmp_path):
        log_file = tmp_path / "usage.jsonl"
        logger = UsageLogger(log_path=str(log_file))
        logger.record(self._make_record(tool_name="first"))
        first_history = logger.load_history()
        assert len(first_history) == 1
        logger.record(self._make_record(tool_name="second"))
        second_history = logger.load_history()
        assert first_history is not second_history
        assert len(second_history) == 2

    def test_load_history_skips_malformed_lines(self, tmp_path):
        log_file = tmp_path / "usage.jsonl"
        logger = UsageLogger(log_path=str(log_file))
        logger.record(self._make_record(tool_name="valid1"))
        # Append a malformed line directly
        with open(log_file, "a") as f:
            f.write("not valid json\n")
        # Invalidate cache
        logger._history_cache = None
        logger.record(self._make_record(tool_name="valid2"))
        history = logger.load_history()
        assert len(history) == 2
        assert history[0].tool_name == "valid1"
        assert history[1].tool_name == "valid2"

    def test_load_history_rejects_symlink(self, tmp_path):
        real_file = tmp_path / "real.jsonl"
        real_file.write_text('{"tool_name":"x","timestamp":1.0,"success":true,"error_message":null,"response_time_ms":10,"argument_keys":[],"session_id":""}\n')
        link = tmp_path / "link.jsonl"
        link.symlink_to(real_file)
        logger = UsageLogger(log_path=str(link))
        assert logger.load_history() == []

    def test_load_history_skips_unknown_fields_in_dict(self, tmp_path):
        log_file = tmp_path / "usage.jsonl"
        data = {
            "tool_name": "my_tool",
            "timestamp": 1.0,
            "success": True,
            "error_message": None,
            "response_time_ms": 100,
            "argument_keys": [],
            "session_id": "",
            "extra_field": "should be ignored",
        }
        log_file.write_text(json.dumps(data) + "\n")
        logger = UsageLogger(log_path=str(log_file))
        history = logger.load_history()
        assert len(history) == 1
        assert history[0].tool_name == "my_tool"


# ---------------------------------------------------------------------------
# TestUsageLoggerMergedStats
# ---------------------------------------------------------------------------

def _write_old_record(log_file, tool_name: str, timestamp: float,
                      session_id: str = "old-session-999",
                      success: bool = True, response_time_ms: int = 100):
    """Write a JSONL record directly to a file (simulating a previous session)."""
    data = {
        "tool_name": tool_name,
        "timestamp": timestamp,
        "success": success,
        "error_message": None if success else "err",
        "response_time_ms": response_time_ms,
        "argument_keys": [],
        "session_id": session_id,
    }
    with open(log_file, "a") as f:
        f.write(json.dumps(data) + "\n")
    os.chmod(str(log_file), 0o600)


class TestUsageLoggerMergedStats:
    def _make_record(self, tool_name: str = "test_tool", success: bool = True,
                     response_time_ms: int = 100, timestamp: float | None = None) -> UsageRecord:
        return UsageRecord(
            tool_name=tool_name,
            timestamp=timestamp or time.time(),
            success=success,
            error_message=None if success else "err",
            response_time_ms=response_time_ms,
            argument_keys=[],
        )

    def test_get_records_includes_file_history(self, tmp_path):
        log_file = tmp_path / "usage.jsonl"
        _write_old_record(log_file, "old_tool", timestamp=100.0)
        logger = UsageLogger(log_path=str(log_file))
        logger.record(self._make_record(tool_name="new_tool", timestamp=200.0))
        records = logger.get_records()
        assert len(records) == 2
        assert records[0].tool_name == "old_tool"
        assert records[1].tool_name == "new_tool"

    def test_get_records_no_duplicates(self, tmp_path):
        log_file = tmp_path / "usage.jsonl"
        logger = UsageLogger(log_path=str(log_file))
        logger.record(self._make_record(tool_name="a", timestamp=100.0))
        logger.record(self._make_record(tool_name="b", timestamp=200.0))
        records = logger.get_records()
        assert len(records) == 2

    def test_get_records_file_history_before_memory(self, tmp_path):
        log_file = tmp_path / "usage.jsonl"
        _write_old_record(log_file, "old_tool", timestamp=100.0)
        logger = UsageLogger(log_path=str(log_file))
        logger.record(self._make_record(tool_name="new_tool", timestamp=200.0))
        records = logger.get_records()
        assert records[0].timestamp == 100.0
        assert records[1].timestamp == 200.0

    def test_get_records_filtered_spans_file_and_memory(self, tmp_path):
        log_file = tmp_path / "usage.jsonl"
        _write_old_record(log_file, "alpha", timestamp=100.0)
        _write_old_record(log_file, "beta", timestamp=101.0)
        logger = UsageLogger(log_path=str(log_file))
        logger.record(self._make_record(tool_name="alpha", timestamp=200.0))
        logger.record(self._make_record(tool_name="gamma", timestamp=201.0))
        alpha_records = logger.get_records(tool_name="alpha")
        assert len(alpha_records) == 2
        assert alpha_records[0].timestamp == 100.0
        assert alpha_records[1].timestamp == 200.0

    def test_get_stats_includes_file_history(self, tmp_path):
        log_file = tmp_path / "usage.jsonl"
        _write_old_record(log_file, "my_tool", timestamp=100.0, response_time_ms=100)
        logger = UsageLogger(log_path=str(log_file))
        logger.record(self._make_record(tool_name="my_tool", timestamp=200.0, response_time_ms=200))
        stats = logger.get_stats()
        assert stats["my_tool"]["total_calls"] == 2

    def test_get_stats_no_double_counting(self, tmp_path):
        log_file = tmp_path / "usage.jsonl"
        logger = UsageLogger(log_path=str(log_file))
        logger.record(self._make_record(tool_name="my_tool", timestamp=100.0))
        stats = logger.get_stats()
        assert stats["my_tool"]["total_calls"] == 1

    def test_get_records_no_file_path_returns_memory_only(self):
        logger = UsageLogger(log_path=None)
        logger.record(self._make_record(tool_name="mem_tool", timestamp=100.0))
        records = logger.get_records()
        assert len(records) == 1
        assert records[0].tool_name == "mem_tool"
