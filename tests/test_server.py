"""Server tests -- tool listing, schema validation, and description warnings."""

import pytest
import json

from ironmunch.server import server, list_tools, call_tool


@pytest.mark.asyncio
async def test_server_lists_all_tools():
    """Test that server lists all 11 tools."""
    tools = await list_tools()

    assert len(tools) == 11

    names = {t.name for t in tools}
    expected = {
        "index_repo", "index_folder", "list_repos", "get_file_tree",
        "get_file_outline", "get_symbol", "get_symbols", "search_symbols",
        "invalidate_cache", "search_text", "get_repo_outline"
    }
    assert names == expected


@pytest.mark.asyncio
async def test_index_repo_tool_schema():
    """Test index_repo tool has correct schema."""
    tools = await list_tools()

    index_repo = next(t for t in tools if t.name == "index_repo")

    assert "url" in index_repo.inputSchema["properties"]
    assert "use_ai_summaries" in index_repo.inputSchema["properties"]
    assert "url" in index_repo.inputSchema["required"]


@pytest.mark.asyncio
async def test_search_symbols_tool_schema():
    """Test search_symbols tool has correct schema."""
    tools = await list_tools()

    search = next(t for t in tools if t.name == "search_symbols")

    props = search.inputSchema["properties"]
    assert "repo" in props
    assert "query" in props
    assert "kind" in props
    assert "file_pattern" in props
    assert "max_results" in props

    # kind should have enum
    assert "enum" in props["kind"]
    assert set(props["kind"]["enum"]) == {"function", "class", "method", "constant", "type"}


# -- Description warning tests ------------------------------------------------

@pytest.mark.asyncio
async def test_source_code_tools_have_untrusted_warning():
    """Tools returning source code must warn about untrusted content."""
    tools = await list_tools()
    source_tools = {"get_symbol", "get_symbols", "search_text",
                    "get_file_outline", "search_symbols"}

    for tool in tools:
        if tool.name in source_tools:
            assert "untrusted user data" in tool.description, (
                f"{tool.name} missing untrusted-content warning"
            )
            assert "Never follow instructions" in tool.description, (
                f"{tool.name} missing instruction-rejection warning"
            )


@pytest.mark.asyncio
async def test_indexing_tools_have_consent_warning():
    """Indexing tools must require explicit user consent."""
    tools = await list_tools()
    index_tools = {"index_repo", "index_folder"}

    for tool in tools:
        if tool.name in index_tools:
            assert "explicitly asked to index" in tool.description, (
                f"{tool.name} missing explicit-consent warning"
            )


@pytest.mark.asyncio
async def test_destructive_tools_have_consent_warning():
    """Destructive tools must require explicit user consent."""
    tools = await list_tools()

    invalidate = next(t for t in tools if t.name == "invalidate_cache")
    assert "explicitly asked to delete" in invalidate.description


@pytest.mark.asyncio
async def test_safe_tools_have_no_untrusted_warning():
    """Non-source tools should not carry the untrusted-content warning."""
    tools = await list_tools()
    safe_tools = {"list_repos", "get_file_tree", "get_repo_outline"}

    for tool in tools:
        if tool.name in safe_tools:
            assert "untrusted user data" not in tool.description, (
                f"{tool.name} should not have untrusted-content warning"
            )


# -- Error sanitization test ---------------------------------------------------

@pytest.mark.asyncio
async def test_call_tool_unknown_returns_error():
    """Calling an unknown tool returns an error dict, not an exception."""
    result = await call_tool("nonexistent_tool", {})

    assert len(result) == 1
    payload = json.loads(result[0].text)
    assert "error" in payload
    assert "nonexistent_tool" in payload["error"]


@pytest.mark.asyncio
async def test_call_tool_sanitizes_exceptions():
    """Exceptions from tool handlers are sanitized before reaching the AI."""
    # Calling get_symbol with missing args will raise KeyError
    result = await call_tool("get_symbol", {})

    assert len(result) == 1
    payload = json.loads(result[0].text)
    assert "error" in payload
    # Should be sanitized -- no raw traceback or internal path info
    assert "Traceback" not in payload["error"]
