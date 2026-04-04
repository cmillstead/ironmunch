"""HTTP error and validation tests for the index_repo tool (TEST-MED-5)."""

import asyncio
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from codesight_mcp.tools.index_repo import index_repo


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
        "codesight_mcp.tools.index_repo.fetch_repo_tree",
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
        "codesight_mcp.tools.index_repo.fetch_repo_tree",
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


@pytest.mark.asyncio
async def test_index_repo_warnings_not_overwritten(tmp_path, monkeypatch):
    """Regression: line 165 must not overwrite parse-failure warnings."""
    from unittest.mock import AsyncMock, patch
    from codesight_mcp.tools.index_repo import index_repo
    from codesight_mcp.core.limits import MAX_FILE_COUNT

    source_files = [f"file_{i}.py" for i in range(MAX_FILE_COUNT)]
    tree_entries = [{"path": f, "type": "blob"} for f in source_files]

    with patch("codesight_mcp.tools.index_repo.fetch_repo_tree", new_callable=AsyncMock) as mock_tree, \
         patch("codesight_mcp.tools.index_repo.fetch_gitignore", new_callable=AsyncMock) as mock_gi, \
         patch("codesight_mcp.tools.index_repo.discover_source_files") as mock_disc, \
         patch("codesight_mcp.tools.index_repo.fetch_file_content", new_callable=AsyncMock) as mock_fetch, \
         patch("codesight_mcp.tools._indexing_common.parse_file") as mock_parse, \
         patch("codesight_mcp.tools._indexing_common.summarize_symbols") as mock_sum, \
         patch("codesight_mcp.tools._indexing_common.IndexStore") as mock_store_cls:

        mock_tree.return_value = tree_entries
        mock_gi.return_value = ""
        mock_disc.return_value = source_files

        call_count = 0

        async def fake_fetch(owner, repo, path, token):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return "def foo(): pass"
            if call_count == 2:
                return "bad content"
            return ""

        mock_fetch.side_effect = fake_fetch

        parse_calls = 0

        def fake_parse(content, path, lang):
            nonlocal parse_calls
            parse_calls += 1
            if parse_calls == 1:
                from codesight_mcp.parser import Symbol
                return [Symbol(
                    id=f"{path}::foo", file=path, name="foo",
                    qualified_name="foo", kind="function", language="python",
                    signature="def foo():", summary="",
                    byte_offset=0, byte_length=len(content),
                )]
            raise ValueError("parse boom")

        mock_parse.side_effect = fake_parse
        mock_sum.side_effect = lambda syms, use_ai: syms

        mock_store = mock_store_cls.return_value
        mock_index = type("FakeIndex", (), {"indexed_at": "2026-01-01T00:00:00"})()
        mock_store.load_index.return_value = mock_index

        monkeypatch.setenv("GITHUB_TOKEN", "fake")

        result = await index_repo("owner/repo", use_ai_summaries=False, storage_path=str(tmp_path))

        assert result["success"] is True
        assert any("failed to parse" in w for w in result.get("warnings", []))
        assert any("many files" in w for w in result.get("warnings", []))
