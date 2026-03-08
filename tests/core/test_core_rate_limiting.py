"""Tests for core.rate_limiting module."""

from codesight_mcp.core.rate_limiting import _rate_limit, _rate_limit_state_dir


def test_rate_limit_allows_first_call(tmp_path):
    assert _rate_limit("test_tool", str(tmp_path)) is True


def test_rate_limit_state_dir_uses_storage_path(tmp_path):
    result = _rate_limit_state_dir(str(tmp_path))
    assert result == tmp_path


def test_rate_limit_respects_per_tool_limit(tmp_path):
    for _ in range(60):
        assert _rate_limit("test_tool", str(tmp_path)) is True
    assert _rate_limit("test_tool", str(tmp_path)) is False
    assert _rate_limit("other_tool", str(tmp_path)) is True
