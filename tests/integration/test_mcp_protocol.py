"""P0-10: MCP protocol registration and dispatch tests.

Verify that all 24 tools are registered with correct schemas and that
the server dispatch works correctly.
"""

import json


from codesight_mcp.server import call_tool, list_tools
from codesight_mcp.tools.registry import get_all_specs


# The 28 expected tool names.
EXPECTED_TOOLS = sorted([
    "index_repo",
    "index_folder",
    "list_repos",
    "get_file_tree",
    "get_file_outline",
    "get_symbol",
    "get_symbols",
    "search_symbols",
    "invalidate_cache",
    "search_text",
    "get_repo_outline",
    "get_callers",
    "get_callees",
    "get_call_chain",
    "get_type_hierarchy",
    "get_imports",
    "get_impact",
    "get_dead_code",
    "get_status",
    "analyze_complexity",
    "get_key_symbols",
    "get_diagram",
    "get_symbol_context",
    "search_references",
    "get_dependencies",
    "compare_symbols",
    "get_changes",
    "get_usage_stats",
])


class TestToolRegistration:
    """Verify all 28 tools are present in the registry."""

    def test_all_22_tools_registered(self):
        """The registry must contain exactly 28 tools."""
        specs = get_all_specs()
        assert len(specs) == 28, (
            f"Expected 28 tools, got {len(specs)}: {sorted(specs.keys())}"
        )

    def test_all_expected_tool_names_present(self):
        """Every expected tool name must be in the registry."""
        specs = get_all_specs()
        registered_names = sorted(specs.keys())
        assert registered_names == EXPECTED_TOOLS, (
            f"Missing: {set(EXPECTED_TOOLS) - set(registered_names)}, "
            f"Extra: {set(registered_names) - set(EXPECTED_TOOLS)}"
        )

    def test_each_spec_has_required_fields(self):
        """Each ToolSpec must have name, description, input_schema, and handler."""
        specs = get_all_specs()
        for name, spec in specs.items():
            assert spec.name == name, f"Spec name mismatch: {spec.name} != {name}"
            assert spec.description, f"Tool {name} has empty description"
            assert isinstance(spec.input_schema, dict), (
                f"Tool {name} input_schema is not a dict"
            )
            assert callable(spec.handler), f"Tool {name} handler is not callable"

    def test_input_schemas_have_type_object(self):
        """Each tool's input_schema must declare type=object."""
        specs = get_all_specs()
        for name, spec in specs.items():
            assert spec.input_schema.get("type") == "object", (
                f"Tool {name} input_schema missing type=object"
            )

    def test_input_schemas_have_properties(self):
        """Each tool's input_schema must have a 'properties' key."""
        specs = get_all_specs()
        for name, spec in specs.items():
            assert "properties" in spec.input_schema, (
                f"Tool {name} input_schema missing 'properties'"
            )


class TestListToolsHandler:
    """Verify the @server.list_tools() handler returns correct Tool objects."""

    async def test_list_tools_returns_all_22(self):
        """The list_tools handler returns exactly 28 Tool objects."""
        tools = await list_tools()
        assert len(tools) == 28, (
            f"Expected 28 tools from list_tools(), got {len(tools)}: "
            f"{[t.name for t in tools]}"
        )

    async def test_list_tools_tool_objects_have_required_fields(self):
        """Each Tool returned by list_tools has name, description, inputSchema."""
        tools = await list_tools()
        for tool in tools:
            assert tool.name, f"Tool missing name: {tool}"
            assert tool.description, f"Tool {tool.name} missing description"
            assert tool.inputSchema, f"Tool {tool.name} missing inputSchema"
            assert isinstance(tool.inputSchema, dict)

    async def test_list_tools_names_match_registry(self):
        """Tool names from list_tools must match the registry exactly."""
        tools = await list_tools()
        tool_names = sorted(t.name for t in tools)
        assert tool_names == EXPECTED_TOOLS

    async def test_list_tools_descriptions_include_warnings(self):
        """Tools with warning flags should have warning text appended."""
        tools = await list_tools()
        tools_by_name = {t.name: t for t in tools}

        # index_repo and index_folder have index_gate warning
        for name in ("index_repo", "index_folder"):
            assert "explicitly asked to index" in tools_by_name[name].description, (
                f"Tool {name} missing index_gate warning"
            )

        # invalidate_cache has destructive warning
        assert "explicitly asked to delete" in tools_by_name["invalidate_cache"].description, (
            "invalidate_cache missing destructive warning"
        )



class TestMCPProtocol:
    """Verify MCP tool annotations are present and correctly classified."""

    async def test_list_tools_annotations_present(self):
        """Every tool returned by list_tools has ToolAnnotations."""
        tools = await list_tools()
        for tool in tools:
            assert tool.annotations is not None, f"Tool {tool.name} missing annotations"
            assert isinstance(tool.annotations.readOnlyHint, bool), (
                f"Tool {tool.name} readOnlyHint not set"
            )

    async def test_list_tools_read_only_tools(self):
        """Read-only tools have readOnlyHint=True."""
        tools = await list_tools()
        tools_by_name = {t.name: t for t in tools}
        read_only = [
            "get_callers", "get_callees", "get_call_chain", "get_type_hierarchy",
            "get_imports", "get_impact", "get_dead_code", "get_status",
            "get_file_outline", "get_file_tree", "get_repo_outline",
            "get_symbol", "get_symbols", "get_symbol_context", "get_key_symbols",
            "get_diagram", "get_dependencies", "get_changes", "get_usage_stats",
            "search_symbols", "search_text", "search_references",
            "analyze_complexity", "compare_symbols", "list_repos",
        ]
        for name in read_only:
            ann = tools_by_name[name].annotations
            assert ann.readOnlyHint is True, f"{name} should be readOnlyHint=True"
            assert ann.openWorldHint is False, f"{name} should be openWorldHint=False"

    async def test_list_tools_write_tools(self):
        """Write tools have correct destructive/idempotent hints."""
        tools = await list_tools()
        tools_by_name = {t.name: t for t in tools}

        ann = tools_by_name["index_repo"].annotations
        assert ann.readOnlyHint is False
        assert ann.destructiveHint is False
        assert ann.idempotentHint is True
        assert ann.openWorldHint is True

        ann = tools_by_name["index_folder"].annotations
        assert ann.readOnlyHint is False
        assert ann.destructiveHint is False
        assert ann.idempotentHint is True
        assert ann.openWorldHint is True

        ann = tools_by_name["invalidate_cache"].annotations
        assert ann.readOnlyHint is False
        assert ann.destructiveHint is True
        assert ann.idempotentHint is True
        assert ann.openWorldHint is False

    async def test_list_tools_annotations_have_titles(self):
        """Every tool has a human-readable title in annotations."""
        tools = await list_tools()
        for tool in tools:
            assert tool.annotations.title, f"Tool {tool.name} missing title"
            assert tool.annotations.title != tool.name, (
                f"Tool {tool.name} title should be human-readable, not the tool name"
            )

    async def test_list_tools_annotation_classification_exhaustive(self):
        """Every tool is classified in exactly one annotation bucket."""
        tools = await list_tools()
        read_only = {
            "get_callers", "get_callees", "get_call_chain", "get_type_hierarchy",
            "get_imports", "get_impact", "get_dead_code", "get_status",
            "get_file_outline", "get_file_tree", "get_repo_outline",
            "get_symbol", "get_symbols", "get_symbol_context", "get_key_symbols",
            "get_diagram", "get_dependencies", "get_changes", "get_usage_stats",
            "search_symbols", "search_text", "search_references",
            "analyze_complexity", "compare_symbols", "list_repos",
        }
        write_tools = {"index_repo", "index_folder"}
        destructive_tools = {"invalidate_cache"}
        classified = read_only | write_tools | destructive_tools
        actual = {t.name for t in tools}
        assert classified == actual, (
            f"Unclassified tools: {actual - classified}, "
            f"Extra classifications: {classified - actual}"
        )


class TestUnknownToolDispatch:
    """Verify calling an unknown tool returns an error."""

    async def test_unknown_tool_returns_error(self):
        """Calling a tool that doesn't exist returns a JSON error."""
        result = await call_tool("nonexistent_tool", {})
        assert len(result) == 1
        payload = json.loads(result[0].text)
        assert "error" in payload
        assert "Unknown tool" in payload["error"]
        assert "nonexistent_tool" in payload["error"]

    async def test_unknown_tool_with_arguments_returns_error(self):
        """Unknown tool with arguments still returns an error."""
        result = await call_tool("fake_tool", {"repo": "test", "query": "hello"})
        assert len(result) == 1
        payload = json.loads(result[0].text)
        assert "error" in payload


class TestStatusToolDispatch:
    """Verify that the 'status' tool can be dispatched through call_tool."""

    async def test_status_tool_returns_valid_response(self, tmp_path, monkeypatch):
        """Dispatching the 'status' tool via call_tool returns storage info."""
        # Point CODE_INDEX_PATH to our temp dir so status uses it
        monkeypatch.setattr(
            "codesight_mcp.server._CODE_INDEX_PATH", str(tmp_path)
        )
        result = await call_tool("get_status", {})
        assert len(result) == 1
        payload = json.loads(result[0].text)
        assert "error" not in payload, f"Unexpected error: {payload}"
        assert "storage_configured" in payload
        assert "repo_count" in payload
        assert "total_symbols" in payload
        assert "version" in payload
        assert isinstance(payload["repo_count"], int)
        assert isinstance(payload["total_symbols"], int)

    async def test_status_tool_shows_zero_repos_on_empty_storage(self, tmp_path, monkeypatch):
        """An empty storage directory should report 0 repos and 0 symbols."""
        monkeypatch.setattr(
            "codesight_mcp.server._CODE_INDEX_PATH", str(tmp_path)
        )
        result = await call_tool("get_status", {})
        payload = json.loads(result[0].text)
        assert payload["repo_count"] == 0
        assert payload["total_symbols"] == 0


class TestArgumentSanitization:
    """Verify that argument validation works through the dispatch layer."""

    async def test_empty_search_query_rejected(self):
        """An empty query for search_symbols is rejected."""
        result = await call_tool("search_symbols", {"repo": "test", "query": ""})
        payload = json.loads(result[0].text)
        assert "error" in payload
        assert "empty" in payload["error"].lower()

    async def test_oversized_argument_rejected(self):
        """An argument exceeding MAX_ARGUMENT_LENGTH is rejected."""
        result = await call_tool("search_symbols", {
            "repo": "test",
            "query": "x" * 100_000,
        })
        payload = json.loads(result[0].text)
        assert "error" in payload
        assert "maximum length" in payload["error"].lower() or "exceeds" in payload["error"].lower()

    async def test_boolean_coercion(self, tmp_path, monkeypatch):
        """Integer 1 should be coerced to True for boolean flags."""
        monkeypatch.setattr(
            "codesight_mcp.server._CODE_INDEX_PATH", str(tmp_path)
        )
        # list_repos doesn't need special args; test with invalidate_cache
        # which has confirm=True. Passing confirm=1 should be coerced to True.
        result = await call_tool("invalidate_cache", {
            "repo": "nonexistent/repo",
            "confirm": 1,
        })
        payload = json.loads(result[0].text)
        # It should not fail due to type error on confirm; it may fail
        # because the repo doesn't exist, which is fine.
        if "error" in payload:
            assert "boolean" not in payload["error"].lower()
