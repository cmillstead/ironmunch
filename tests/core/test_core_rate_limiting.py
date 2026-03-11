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


def test_rate_limit_fails_closed_after_threshold(tmp_path):
    """After consecutive state-dir write failures, rate_limit should deny calls."""
    import os
    from unittest.mock import patch
    from codesight_mcp.core import rate_limiting

    # Reset failure counter
    rate_limiting._consecutive_write_failures = 0

    # Simulate write failures by making atomic_write_nofollow always raise
    def fail_write(*args, **kwargs):
        raise OSError("disk full")

    with patch("codesight_mcp.core.rate_limiting.atomic_write_nofollow", side_effect=fail_write):
        # First _MAX_WRITE_FAILURES calls should still allow (optimistic)
        for i in range(rate_limiting._MAX_WRITE_FAILURES):
            result = _rate_limit(f"tool_{i}", str(tmp_path))
            assert result is True, f"Call {i} should be allowed"

        # After threshold, should fail closed
        result = _rate_limit("tool_blocked", str(tmp_path))
        assert result is False, "Should deny after too many write failures"

    # Reset for other tests
    rate_limiting._consecutive_write_failures = 0
