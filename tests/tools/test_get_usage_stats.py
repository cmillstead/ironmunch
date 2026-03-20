"""Tests for get_usage_stats tool."""

from codesight_mcp.core.usage_logging import UsageLogger, UsageRecord
from codesight_mcp.tools.get_usage_stats import get_usage_stats


class TestGetUsageStats:
    def _make_logger(self, records=None):
        logger = UsageLogger(max_memory=1000, log_path=None)
        for rec in records or []:
            logger.record(rec)
        return logger

    def test_returns_empty_stats(self):
        logger = self._make_logger()
        all_tools = ["a", "b", "c"]
        result = get_usage_stats(logger=logger, all_tool_names=all_tools)
        assert result["total_calls"] == 0
        assert result["per_tool"] == {}
        assert sorted(result["uncalled_tools"]) == ["a", "b", "c"]

    def test_returns_per_tool_stats(self):
        records = [
            UsageRecord(tool_name="a", timestamp=1.0, success=True, error_message=None, response_time_ms=100),
            UsageRecord(tool_name="a", timestamp=2.0, success=False, error_message="err", response_time_ms=200),
            UsageRecord(tool_name="b", timestamp=3.0, success=True, error_message=None, response_time_ms=50),
        ]
        logger = self._make_logger(records)
        all_tools = ["a", "b", "c"]
        result = get_usage_stats(logger=logger, all_tool_names=all_tools)
        assert result["total_calls"] == 3
        assert result["per_tool"]["a"]["total_calls"] == 2
        assert result["per_tool"]["a"]["success_count"] == 1
        assert result["per_tool"]["a"]["error_count"] == 1
        assert result["per_tool"]["b"]["total_calls"] == 1
        assert result["uncalled_tools"] == ["c"]

    def test_get_usage_stats_excluded_from_uncalled(self):
        logger = self._make_logger()
        all_tools = ["a", "get_usage_stats", "b"]
        result = get_usage_stats(logger=logger, all_tool_names=all_tools)
        assert "get_usage_stats" not in result["uncalled_tools"]
        assert sorted(result["uncalled_tools"]) == ["a", "b"]

    def test_meta_envelope(self):
        logger = self._make_logger()
        result = get_usage_stats(logger=logger, all_tool_names=[])
        meta = result["_meta"]
        assert meta["source"] == "usage_stats"
        assert meta["contentTrust"] == "trusted"
        assert "timing_ms" in meta

    def test_filter_by_tool_name(self):
        records = [
            UsageRecord(tool_name="a", timestamp=1.0, success=True, error_message=None, response_time_ms=100),
            UsageRecord(tool_name="b", timestamp=2.0, success=True, error_message=None, response_time_ms=200),
        ]
        logger = self._make_logger(records)
        all_tools = ["a", "b", "c"]
        result = get_usage_stats(logger=logger, all_tool_names=all_tools, tool_name="a")
        assert "a" in result["per_tool"]
        assert "b" not in result["per_tool"]
        assert result["total_calls"] == 1
