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


# -- Input bounds tests --------------------------------------------------------

class TestCallToolInputBounds:
    @pytest.mark.asyncio
    async def test_oversized_string_argument_rejected(self):
        result = await call_tool("search_text", {
            "repo": "test/repo",
            "query": "x" * 20_000,
        })
        text = result[0].text
        assert "error" in text.lower()
        assert "maximum length" in text.lower()

    @pytest.mark.asyncio
    async def test_empty_search_query_rejected(self):
        result = await call_tool("search_text", {
            "repo": "test/repo",
            "query": "",
        })
        text = result[0].text
        assert "error" in text.lower()
        assert "empty" in text.lower()

    @pytest.mark.asyncio
    async def test_whitespace_only_query_rejected(self):
        result = await call_tool("search_text", {
            "repo": "test/repo",
            "query": "   ",
        })
        text = result[0].text
        assert "error" in text.lower()
        assert "empty" in text.lower()

    @pytest.mark.asyncio
    async def test_symbol_ids_list_capped(self):
        result = await call_tool("get_symbols", {
            "repo": "test/repo",
            "symbol_ids": [f"sym_{i}" for i in range(200)],
        })
        # Should not crash -- repo won't exist but that's fine
        text = result[0].text
        assert "error" in text.lower()  # repo not found, but it didn't crash

    def test_string_false_is_falsy(self):
        """String 'false' must be coerced to False for boolean flags."""
        from ironmunch.server import _sanitize_arguments
        args = {"follow_symlinks": "false", "path": "/test"}
        result = _sanitize_arguments("index_folder", args)
        assert isinstance(result, dict)
        assert result["follow_symlinks"] is False

    def test_string_true_is_falsy_too(self):
        """String 'true' is not in (True, 1) so it should be False."""
        from ironmunch.server import _sanitize_arguments
        args = {"verify": "true"}
        result = _sanitize_arguments("get_symbol", args)
        assert isinstance(result, dict)
        assert result["verify"] is False

    def test_actual_bool_true_preserved(self):
        """Actual boolean True must be preserved."""
        from ironmunch.server import _sanitize_arguments
        args = {"follow_symlinks": True, "path": "/test"}
        result = _sanitize_arguments("index_folder", args)
        assert isinstance(result, dict)
        assert result["follow_symlinks"] is True

    def test_symbol_ids_oversized_items_filtered(self):
        """SEC-LOW-3: oversized symbol_ids must be filtered."""
        from ironmunch.server import _sanitize_arguments, MAX_ARGUMENT_LENGTH
        args = {"repo": "test/repo", "symbol_ids": ["ok", "x" * (MAX_ARGUMENT_LENGTH + 1)]}
        result = _sanitize_arguments("get_symbols", args)
        assert isinstance(result, dict)
        assert len(result["symbol_ids"]) == 1
        assert result["symbol_ids"][0] == "ok"

    def test_file_pattern_capped(self):
        """SEC-LOW-6: file_pattern must be capped to MAX_FILE_PATTERN_LENGTH."""
        from ironmunch.server import _sanitize_arguments
        from ironmunch.core.limits import MAX_FILE_PATTERN_LENGTH
        args = {"repo": "test/repo", "query": "foo", "file_pattern": "x" * 500}
        result = _sanitize_arguments("search_text", args)
        assert isinstance(result, dict)
        assert len(result["file_pattern"]) == MAX_FILE_PATTERN_LENGTH


class TestRateLimiting:
    """M-5: Rate limiting prevents tool call flooding."""

    def test_rate_limit_applied(self):
        """Excessive calls to the same tool should be rate-limited."""
        from ironmunch.server import _rate_limit, _CALL_TIMESTAMPS
        # Clear any prior state
        _CALL_TIMESTAMPS.clear()
        blocked = 0
        for _ in range(100):
            if not _rate_limit("test_tool"):
                blocked += 1
        assert blocked > 0, "Rate limiting never kicked in"

    def test_rate_limit_allows_normal_usage(self):
        """A few calls should not be blocked."""
        from ironmunch.server import _rate_limit, _CALL_TIMESTAMPS
        _CALL_TIMESTAMPS.clear()
        for _ in range(5):
            assert _rate_limit("normal_tool") is True


# -- SEC-HIGH-1: unknown tool names rejected before rate limit ----------------

class TestUnknownToolRejectedBeforeRateLimit:
    """SEC-HIGH-1: Unknown tool names must be rejected before rate limiting."""

    @pytest.mark.asyncio
    async def test_unknown_tool_returns_error_and_does_not_consume_global_slot(self):
        """Calling an unknown tool returns an error AND does not touch _GLOBAL_TIMESTAMPS."""
        import ironmunch.server as server_module
        # Clear global rate limit state so we start fresh
        server_module._GLOBAL_TIMESTAMPS.clear()
        server_module._CALL_TIMESTAMPS.clear()

        result = await call_tool("totally_fake_tool", {})

        # Must return an error response
        assert len(result) == 1
        payload = json.loads(result[0].text)
        assert "error" in payload
        assert "totally_fake_tool" in payload["error"]

        # Must NOT have consumed any global rate limit slot
        assert len(server_module._GLOBAL_TIMESTAMPS) == 0, (
            "Unknown tool call must not increment _GLOBAL_TIMESTAMPS"
        )

    @pytest.mark.asyncio
    async def test_many_fake_tool_calls_do_not_exhaust_global_rate_limit(self):
        """Flooding with fabricated tool names must not fill _GLOBAL_TIMESTAMPS."""
        import ironmunch.server as server_module
        server_module._GLOBAL_TIMESTAMPS.clear()
        server_module._CALL_TIMESTAMPS.clear()

        # Simulate many fake tool calls (well above the global limit of 120)
        for i in range(150):
            await call_tool(f"fake_tool_{i}", {})

        # Global timestamps must remain empty — no slots were consumed
        assert len(server_module._GLOBAL_TIMESTAMPS) == 0, (
            f"Expected 0 global timestamps after fake calls, "
            f"got {len(server_module._GLOBAL_TIMESTAMPS)}"
        )
