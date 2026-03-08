"""Tests for resource limit constants."""

from codesight_mcp.core.limits import (
    MAX_FILE_SIZE,
    MAX_FILE_COUNT,
    MAX_CONTEXT_LINES,
    MAX_PATH_LENGTH,
    MAX_DIRECTORY_DEPTH,
    MAX_INDEX_SIZE,
    MAX_SEARCH_RESULTS,
    GITHUB_API_TIMEOUT,
)


def test_limits_are_positive():
    for limit in [
        MAX_FILE_SIZE,
        MAX_FILE_COUNT,
        MAX_CONTEXT_LINES,
        MAX_PATH_LENGTH,
        MAX_DIRECTORY_DEPTH,
        MAX_INDEX_SIZE,
        MAX_SEARCH_RESULTS,
        GITHUB_API_TIMEOUT,
    ]:
        assert limit > 0


def test_specific_values():
    assert MAX_FILE_SIZE == 500 * 1024  # 500 KB
    assert MAX_FILE_COUNT == 500
    assert MAX_CONTEXT_LINES == 100
    assert MAX_PATH_LENGTH == 512
    assert MAX_DIRECTORY_DEPTH == 10
    assert MAX_INDEX_SIZE == 50 * 1024 * 1024  # 50 MB
    assert MAX_SEARCH_RESULTS == 50
    assert GITHUB_API_TIMEOUT == 30
