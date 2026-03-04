"""HTTP error and validation tests for the index_repo tool (TEST-MED-5)."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from ironmunch.tools.index_repo import index_repo


def _make_http_status_error(status_code: int) -> httpx.HTTPStatusError:
    """Build an httpx.HTTPStatusError with the given status code."""
    request = httpx.Request("GET", "https://api.github.com/test")
    response = httpx.Response(status_code=status_code, request=request)
    return httpx.HTTPStatusError(
        f"HTTP {status_code}",
        request=request,
        response=response,
    )


def test_index_repo_404_returns_error():
    """A 404 from GitHub API results in an error response."""
    error = _make_http_status_error(404)

    with patch(
        "ironmunch.tools.index_repo.fetch_repo_tree",
        new=AsyncMock(side_effect=error),
    ):
        result = asyncio.run(
            index_repo(
                url="https://github.com/someowner/nonexistent-repo",
                use_ai_summaries=False,
            )
        )

    assert result.get("success") is False
    assert "error" in result
    assert "not found" in result["error"].lower() or "404" in result["error"]


def test_index_repo_403_returns_error():
    """A 403 from GitHub API results in a rate-limit error response."""
    error = _make_http_status_error(403)

    with patch(
        "ironmunch.tools.index_repo.fetch_repo_tree",
        new=AsyncMock(side_effect=error),
    ):
        result = asyncio.run(
            index_repo(
                url="https://github.com/someowner/somerepo",
                use_ai_summaries=False,
            )
        )

    assert result.get("success") is False
    assert "error" in result
    # Should mention rate limit or token
    assert "rate limit" in result["error"].lower() or "github_token" in result["error"].upper()


def test_index_repo_invalid_url_returns_error():
    """Passing a non-GitHub URL returns an error without making any HTTP calls."""
    result = asyncio.run(
        index_repo(
            url="https://gitlab.com/someowner/somerepo",
            use_ai_summaries=False,
        )
    )

    assert result.get("success") is False
    assert "error" in result
