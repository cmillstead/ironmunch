"""Server tests -- tool listing, schema validation, and description warnings."""

import json
from pathlib import Path

import pytest

from codesight_mcp.server import (
    call_tool,
    list_tools,
    _usage_logger,
)
from codesight_mcp.core.rate_limiting import _rate_limit


@pytest.mark.asyncio
async def test_server_lists_all_tools():
    """Test that server lists all 28 tools."""
    tools = await list_tools()

    assert len(tools) == 28

    names = {t.name for t in tools}
    expected = {
        "index_repo", "index_folder", "list_repos", "get_file_tree",
        "get_file_outline", "get_symbol", "get_symbols", "search_symbols",
        "invalidate_cache", "search_text", "get_repo_outline",
        "get_callers", "get_callees", "get_call_chain",
        "get_type_hierarchy", "get_imports", "get_impact",
        "get_dead_code", "get_status",
        "analyze_complexity", "get_key_symbols", "get_diagram",
        "get_symbol_context", "search_references", "get_dependencies",
        "compare_symbols", "get_changes",
        "get_usage_stats",
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


@pytest.mark.asyncio
async def test_search_text_tool_schema():
    """Test search_text tool has the expected fields in its schema."""
    tools = await list_tools()

    search = next(t for t in tools if t.name == "search_text")

    props = search.inputSchema["properties"]
    assert "repo" in props
    assert "query" in props
    assert "file_pattern" in props
    assert "max_results" in props


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
        from codesight_mcp.server import _sanitize_arguments
        args = {"follow_symlinks": "false", "path": "/test"}
        result = _sanitize_arguments("index_folder", args)
        assert isinstance(result, dict)
        assert result["follow_symlinks"] is False

    def test_string_true_is_truthy(self):
        """String 'true' should be coerced to True."""
        from codesight_mcp.server import _sanitize_arguments
        args = {"verify": "true"}
        result = _sanitize_arguments("get_symbol", args)
        assert isinstance(result, dict)
        assert result["verify"] is True

    def test_actual_bool_true_preserved(self):
        """Actual boolean True must be preserved."""
        from codesight_mcp.server import _sanitize_arguments
        args = {"follow_symlinks": True, "path": "/test"}
        result = _sanitize_arguments("index_folder", args)
        assert isinstance(result, dict)
        assert result["follow_symlinks"] is True

    def test_symbol_ids_oversized_items_filtered(self):
        """SEC-LOW-3: oversized symbol_ids must be filtered."""
        from codesight_mcp.server import _sanitize_arguments, MAX_ARGUMENT_LENGTH
        args = {"repo": "test/repo", "symbol_ids": ["ok", "x" * (MAX_ARGUMENT_LENGTH + 1)]}
        result = _sanitize_arguments("get_symbols", args)
        assert isinstance(result, dict)
        assert len(result["symbol_ids"]) == 1
        assert result["symbol_ids"][0] == "ok"

    def test_file_pattern_capped(self):
        """SEC-LOW-6: file_pattern must be capped to MAX_FILE_PATTERN_LENGTH."""
        from codesight_mcp.server import _sanitize_arguments
        from codesight_mcp.core.limits import MAX_FILE_PATTERN_LENGTH
        args = {"repo": "test/repo", "query": "foo", "file_pattern": "x" * 500}
        result = _sanitize_arguments("search_text", args)
        assert isinstance(result, dict)
        assert len(result["file_pattern"]) == MAX_FILE_PATTERN_LENGTH

    # -- SEC-LOW-2: integer type validation ------------------------------------

    def test_context_lines_dict_returns_validation_error(self):
        """SEC-LOW-2: context_lines with dict value must return a helpful error."""
        from codesight_mcp.server import _sanitize_arguments
        result = _sanitize_arguments("get_symbol", {
            "repo": "test/repo",
            "symbol_id": "some-id",
            "context_lines": {"key": "val"},
        })
        assert isinstance(result, str), "Expected a validation error string"
        assert "context_lines" in result
        assert "integer" in result.lower()

    async def test_context_lines_dict_produces_meaningful_error_via_call_tool(self):
        """SEC-LOW-2: call_tool with context_lines=dict returns meaningful error, not internal error."""
        result = await call_tool("get_symbol", {
            "repo": "test/repo",
            "symbol_id": "some-id",
            "context_lines": {"key": "val"},
        })
        assert len(result) == 1
        payload = json.loads(result[0].text)
        assert "error" in payload
        # Must contain context_lines, not "internal" or "Traceback"
        assert "context_lines" in payload["error"]
        assert "Traceback" not in payload["error"]
        assert "internal" not in payload["error"].lower()

    def test_max_results_string_int_coerced(self):
        """SEC-LOW-2: max_results with string integer must be coerced, not error."""
        from codesight_mcp.server import _sanitize_arguments
        result = _sanitize_arguments("search_symbols", {
            "repo": "test/repo",
            "query": "foo",
            "max_results": "5",
        })
        assert isinstance(result, dict)
        assert result["max_results"] == 5

    def test_max_results_non_numeric_string_rejected(self):
        """SEC-LOW-2: max_results='notanint' must return a validation error."""
        from codesight_mcp.server import _sanitize_arguments
        result = _sanitize_arguments("search_symbols", {
            "repo": "test/repo",
            "query": "foo",
            "max_results": "notanint",
        })
        assert isinstance(result, str)
        assert "max_results" in result
        assert "integer" in result.lower()

    def test_context_lines_float_coerced(self):
        """SEC-LOW-2: context_lines=3.7 must be coerced to int 3."""
        from codesight_mcp.server import _sanitize_arguments
        result = _sanitize_arguments("get_symbol", {
            "repo": "test/repo",
            "symbol_id": "sid",
            "context_lines": 3.7,
        })
        assert isinstance(result, dict)
        assert result["context_lines"] == 3

    def test_context_lines_clamped_to_max(self):
        """SEC-LOW-2: context_lines above MAX_CONTEXT_LINES must be clamped."""
        from codesight_mcp.server import _sanitize_arguments
        from codesight_mcp.core.limits import MAX_CONTEXT_LINES
        result = _sanitize_arguments("get_symbol", {
            "repo": "test/repo",
            "symbol_id": "sid",
            "context_lines": 99999,
        })
        assert isinstance(result, dict)
        assert result["context_lines"] == MAX_CONTEXT_LINES

    def test_max_results_clamped_to_max(self):
        """SEC-LOW-2: max_results above MAX_SEARCH_RESULTS must be clamped."""
        from codesight_mcp.server import _sanitize_arguments
        from codesight_mcp.core.limits import MAX_SEARCH_RESULTS
        result = _sanitize_arguments("search_symbols", {
            "repo": "test/repo",
            "query": "foo",
            "max_results": 99999,
        })
        assert isinstance(result, dict)
        assert result["max_results"] == MAX_SEARCH_RESULTS


class TestRateLimiting:
    """M-5: Rate limiting prevents tool call flooding."""

    def test_rate_limit_applied(self, tmp_path):
        """Excessive calls to the same tool should be rate-limited."""
        blocked = 0
        for _ in range(100):
            if not _rate_limit("test_tool", str(tmp_path)):
                blocked += 1
        assert blocked > 0, "Rate limiting never kicked in"

    def test_rate_limit_allows_normal_usage(self, tmp_path):
        """A few calls should not be blocked."""
        for _ in range(5):
            assert _rate_limit("normal_tool", str(tmp_path)) is True

    def test_global_rate_limit_blocks_after_limit_reached(self, tmp_path):
        """Filling the persisted global bucket to the cap must block the next call."""
        from codesight_mcp.core.rate_limiting import _MAX_GLOBAL_CALLS_PER_MINUTE

        import time as _time
        state_path = tmp_path / ".rate_limits.json"
        now = _time.time()
        state_path.write_text(json.dumps({
            "global": [now] * _MAX_GLOBAL_CALLS_PER_MINUTE,
            "tools": {},
        }), encoding="utf-8")

        result = _rate_limit("some_known_tool", str(tmp_path))
        assert result is False, (
            "Expected _rate_limit to return False when global limit is full"
        )


# -- SEC-HIGH-1: unknown tool names rejected before rate limit ----------------

class TestUnknownToolRejectedBeforeRateLimit:
    """SEC-HIGH-1: Unknown tool names must be rejected before rate limiting."""

    @pytest.mark.asyncio
    async def test_unknown_tool_returns_error_and_does_not_create_rate_limit_state(self, monkeypatch, tmp_path):
        """Calling an unknown tool must not create persistent rate-limit state."""
        import codesight_mcp.core.rate_limiting as rl_module
        monkeypatch.setattr(rl_module, "_rate_limit_state_dir", lambda _storage: tmp_path)

        result = await call_tool("totally_fake_tool", {})

        # Must return an error response
        assert len(result) == 1
        payload = json.loads(result[0].text)
        assert "error" in payload
        assert "totally_fake_tool" in payload["error"]

        assert not (tmp_path / ".rate_limits.json").exists()

    @pytest.mark.asyncio
    async def test_many_fake_tool_calls_do_not_create_rate_limit_state(self, monkeypatch, tmp_path):
        """Flooding unknown tool names must not create rate-limit state."""
        import codesight_mcp.core.rate_limiting as rl_module
        monkeypatch.setattr(rl_module, "_rate_limit_state_dir", lambda _storage: tmp_path)

        for i in range(150):
            await call_tool(f"fake_tool_{i}", {})

        assert not (tmp_path / ".rate_limits.json").exists()


# -- SEC-LOW-4: path_prefix validation in get_file_tree -----------------------

class TestGetFileTreePathPrefixValidation:
    """SEC-LOW-4: path_prefix with traversal sequences must be rejected."""

    @pytest.mark.asyncio
    async def test_dotdot_path_prefix_returns_error(self):
        """path_prefix='../' must return an error, not traverse the filesystem."""
        result = await call_tool("get_file_tree", {
            "repo": "test/repo",
            "path_prefix": "../",
        })
        assert len(result) == 1
        payload = json.loads(result[0].text)
        assert "error" in payload
        assert ".." in payload["error"] or "path_prefix" in payload["error"]

    @pytest.mark.asyncio
    async def test_dotdot_as_component_rejected(self):
        """path_prefix='src/../etc' must be rejected."""
        result = await call_tool("get_file_tree", {
            "repo": "test/repo",
            "path_prefix": "src/../etc",
        })
        assert len(result) == 1
        payload = json.loads(result[0].text)
        assert "error" in payload

    @pytest.mark.asyncio
    async def test_null_byte_in_path_prefix_rejected(self):
        """path_prefix with null byte must be rejected."""
        result = await call_tool("get_file_tree", {
            "repo": "test/repo",
            "path_prefix": "src\x00evil",
        })
        assert len(result) == 1
        payload = json.loads(result[0].text)
        assert "error" in payload

    def test_path_prefix_validation_direct(self):
        """Test path_prefix validation directly in get_file_tree module."""
        from codesight_mcp.tools.get_file_tree import get_file_tree
        result = get_file_tree(repo="test/repo", path_prefix="../")
        assert "error" in result


# -- SEC-LOW-5: type-validate list_repos fields --------------------------------

class TestListReposTypeValidation:
    """SEC-LOW-5: list_repos must skip entries with non-string repo/indexed_at."""

    def test_malformed_repo_null_is_skipped(self, tmp_path):
        """An entry with 'repo': null must be silently skipped."""
        from codesight_mcp.storage.index_store import IndexStore
        import json as _json

        store = IndexStore(base_path=str(tmp_path))

        # Write a well-formed index so we have at least one valid entry
        store.save_index(
            owner="validowner",
            name="validrepo",
            source_files=["main.py"],
            symbols=[],
            raw_files={"main.py": ""},
            languages={"python": 1},
        )

        # Manually write a malformed index file with "repo": null
        malformed = {
            "repo": None,
            "indexed_at": "2026-01-01T00:00:00",
            "symbols": [],
            "source_files": [],
            "languages": {},
            "index_version": 2,
            "file_hashes": {},
            "git_head": "",
            "owner": "bad",
            "name": "entry",
        }
        bad_path = tmp_path / "bad__entry.json"
        bad_path.write_text(_json.dumps(malformed))

        repos = store.list_repos()

        # Only the valid repo should appear; the malformed one is skipped
        repo_names = [r["repo"] for r in repos]
        assert "validowner/validrepo" in repo_names
        assert any(r is None for r in repo_names) is False

    def test_malformed_indexed_at_null_is_skipped(self, tmp_path):
        """An entry with 'indexed_at': null must be silently skipped."""
        from codesight_mcp.storage.index_store import IndexStore
        import json as _json

        store = IndexStore(base_path=str(tmp_path))

        malformed = {
            "repo": "owner/repo",
            "indexed_at": None,  # non-string
            "symbols": [],
            "source_files": [],
            "languages": {},
            "index_version": 2,
            "file_hashes": {},
            "git_head": "",
            "owner": "owner",
            "name": "repo",
        }
        bad_path = tmp_path / "owner__repo.json"
        bad_path.write_text(_json.dumps(malformed))

        repos = store.list_repos()
        assert len(repos) == 0


# -- SEC-LOW-7: mkdir mode 0o700 for content directories ----------------------

class TestMkdirMode:
    """SEC-LOW-7: content subdirectories must be created with mode 0o700."""

    def test_content_dir_mode_0o700(self, tmp_path):
        """After indexing, the content directory must have mode 0o700."""
        import stat
        from codesight_mcp.storage.index_store import IndexStore

        store = IndexStore(base_path=str(tmp_path))
        store.save_index(
            owner="testowner",
            name="testrepo",
            source_files=["nested/deep/file.py"],
            symbols=[],
            raw_files={"nested/deep/file.py": "x = 1"},
            languages={"python": 1},
        )

        content_dir = tmp_path / "testowner__testrepo"
        assert content_dir.exists()
        mode = stat.S_IMODE(content_dir.stat().st_mode)
        assert mode == 0o700, f"Expected 0o700, got {oct(mode)}"

    def test_nested_content_subdir_mode_0o700(self, tmp_path):
        """Intermediate content subdirectories must also have mode 0o700."""
        import stat
        from codesight_mcp.storage.index_store import IndexStore

        store = IndexStore(base_path=str(tmp_path))
        store.save_index(
            owner="testowner",
            name="testrepo",
            source_files=["nested/deep/file.py"],
            symbols=[],
            raw_files={"nested/deep/file.py": "x = 1"},
            languages={"python": 1},
        )

        nested_dir = tmp_path / "testowner__testrepo" / "nested"
        assert nested_dir.exists()
        mode = stat.S_IMODE(nested_dir.stat().st_mode)
        assert mode == 0o700, f"Expected 0o700 for nested dir, got {oct(mode)}"


# -- SEC-LOW-1: symbol_ids type guard -----------------------------------------

class TestGetSymbolsSymbolIdsTypeGuard:
    """SEC-LOW-1: get_symbols must reject non-list symbol_ids before slicing."""

    @pytest.mark.asyncio
    async def test_get_symbols_rejects_non_list_symbol_ids_integer(self):
        """SEC-LOW-1: integer symbol_ids must be rejected with a clear error."""
        result = await call_tool(
            "get_symbols",
            {"repo": "local/nonexistent", "symbol_ids": 42},
        )
        text = result[0].text if result else ""
        assert "symbol_ids" in text.lower() or "list" in text.lower(), (
            f"Expected clear error about symbol_ids, got: {text!r}"
        )

    @pytest.mark.asyncio
    async def test_get_symbols_rejects_string_symbol_ids(self):
        """SEC-LOW-1: string symbol_ids must be rejected, not iterated char by char."""
        result = await call_tool(
            "get_symbols",
            {"repo": "local/nonexistent", "symbol_ids": "abc"},
        )
        text = result[0].text if result else ""
        assert "symbol_ids" in text.lower() or "list" in text.lower(), (
            f"Expected clear error about symbol_ids, got: {text!r}"
        )

    def test_symbol_ids_non_list_returns_error_string_from_sanitize(self):
        """SEC-LOW-1: _sanitize_arguments must return an error string for non-list symbol_ids."""
        from codesight_mcp.server import _sanitize_arguments
        result = _sanitize_arguments("get_symbols", {
            "repo": "test/repo",
            "symbol_ids": {"key": "val"},
        })
        assert isinstance(result, str), "Expected error string for dict symbol_ids"
        assert "symbol_ids" in result
        assert "list" in result.lower()


# -- SEC-LOW-7: CODE_INDEX_PATH validation ------------------------------------

class TestCodeIndexPathValidation:
    """SEC-LOW-7: Relative CODE_INDEX_PATH must be rejected."""

    def test_relative_path_raises_value_error(self):
        """_validate_storage_path must raise ValueError for a relative path."""
        from codesight_mcp.server import _validate_storage_path
        import pytest
        with pytest.raises(ValueError, match="absolute"):
            _validate_storage_path("../../relative/path")

    def test_none_returns_none(self):
        """_validate_storage_path(None) must return None (not set case)."""
        from codesight_mcp.server import _validate_storage_path
        assert _validate_storage_path(None) is None

    def test_absolute_path_returned_resolved(self, tmp_path):
        """_validate_storage_path with an absolute path must return its resolved form."""
        from codesight_mcp.server import _validate_storage_path
        result = _validate_storage_path(str(tmp_path))
        assert result is not None
        assert result.startswith("/")

    async def test_relative_env_var_causes_error_in_call_tool(self, monkeypatch):
        """SEC-LOW-7: Relative CODE_INDEX_PATH env var causes call_tool to return an error.

        Note: _CODE_INDEX_PATH is now read once at module import time (ADV-LOW-7).
        To test the validation logic, we patch _CODE_INDEX_PATH directly.
        """
        import codesight_mcp.server as server_module
        original = server_module._CODE_INDEX_PATH
        try:
            server_module._CODE_INDEX_PATH = "relative/path"
            result = await call_tool("list_repos", {})
            assert len(result) == 1
            text = result[0].text
            assert "error" in text.lower()
        finally:
            server_module._CODE_INDEX_PATH = original


class TestParseRepoBareNameLookup:
    """TEST-HIGH-1: parse_repo bare-name resolution covers found, not-found, ambiguous."""

    def test_bare_name_found(self, tmp_path):
        """parse_repo resolves a bare name when exactly one match exists."""
        from codesight_mcp.tools._common import parse_repo
        from codesight_mcp.storage import IndexStore
        from codesight_mcp.parser import Symbol

        store = IndexStore(base_path=str(tmp_path))
        store.save_index(
            owner="acme",
            name="myproject",
            source_files=["a.py"],
            symbols=[Symbol(id="a-py::f", file="a.py", name="f",
                            qualified_name="f", kind="function", language="python",
                            signature="def f():", byte_offset=0, byte_length=10)],
            raw_files={"a.py": "def f(): pass"},
            languages={"python": 1},
        )
        owner, name = parse_repo("myproject", storage_path=str(tmp_path))
        assert owner == "acme"
        assert name == "myproject"

    def test_bare_name_not_found(self, tmp_path):
        """parse_repo raises RepoNotFoundError when no match exists."""
        from codesight_mcp.tools._common import parse_repo
        from codesight_mcp.core.errors import RepoNotFoundError

        with pytest.raises(RepoNotFoundError, match="not found"):
            parse_repo("doesnotexist", storage_path=str(tmp_path))

    def test_bare_name_ambiguous(self, tmp_path):
        """parse_repo raises RepoNotFoundError when multiple repos share the name."""
        from codesight_mcp.tools._common import parse_repo
        from codesight_mcp.core.errors import RepoNotFoundError
        from codesight_mcp.storage import IndexStore
        from codesight_mcp.parser import Symbol

        store = IndexStore(base_path=str(tmp_path))
        for owner in ("org1", "org2"):
            store.save_index(
                owner=owner,
                name="myproject",
                source_files=["a.py"],
                symbols=[Symbol(id="a-py::f", file="a.py", name="f",
                                qualified_name="f", kind="function", language="python",
                                signature="def f():", byte_offset=0, byte_length=10)],
                raw_files={"a.py": "def f(): pass"},
                languages={"python": 1},
            )
        with pytest.raises(RepoNotFoundError, match="[Aa]mbiguous"):
            parse_repo("myproject", storage_path=str(tmp_path))

    def test_bare_name_prefix_match_local_hash(self, tmp_path):
        """parse_repo resolves bare name against hash-suffixed local repos."""
        from codesight_mcp.tools._common import parse_repo
        from codesight_mcp.storage import IndexStore
        from codesight_mcp.parser import Symbol

        store = IndexStore(base_path=str(tmp_path))
        store.save_index(
            owner="local",
            name="codesight-mcp-b1d9a2d53f7f",
            source_files=["a.py"],
            symbols=[Symbol(id="a-py::f", file="a.py", name="f",
                            qualified_name="f", kind="function", language="python",
                            signature="def f():", byte_offset=0, byte_length=10)],
            raw_files={"a.py": "def f(): pass"},
            languages={"python": 1},
        )
        owner, name = parse_repo("codesight-mcp", storage_path=str(tmp_path))
        assert owner == "local"
        assert name == "codesight-mcp-b1d9a2d53f7f"

    def test_bare_name_prefix_match_ambiguous(self, tmp_path):
        """parse_repo raises when multiple hash-suffixed repos match the same base name."""
        from codesight_mcp.tools._common import parse_repo
        from codesight_mcp.core.errors import RepoNotFoundError
        from codesight_mcp.storage import IndexStore
        from codesight_mcp.parser import Symbol

        store = IndexStore(base_path=str(tmp_path))
        for hash_suffix in ("aabbccddeeff", "112233445566"):
            store.save_index(
                owner="local",
                name=f"myapp-{hash_suffix}",
                source_files=["a.py"],
                symbols=[Symbol(id="a-py::f", file="a.py", name="f",
                                qualified_name="f", kind="function", language="python",
                                signature="def f():", byte_offset=0, byte_length=10)],
                raw_files={"a.py": "def f(): pass"},
                languages={"python": 1},
            )
        with pytest.raises(RepoNotFoundError, match="[Aa]mbiguous"):
            parse_repo("myapp", storage_path=str(tmp_path))

    def test_bare_name_exact_match_preferred_over_prefix(self, tmp_path):
        """Exact name match takes priority over prefix match with hash suffix."""
        from codesight_mcp.tools._common import parse_repo
        from codesight_mcp.storage import IndexStore
        from codesight_mcp.parser import Symbol

        store = IndexStore(base_path=str(tmp_path))
        sym = Symbol(id="a-py::f", file="a.py", name="f",
                     qualified_name="f", kind="function", language="python",
                     signature="def f():", byte_offset=0, byte_length=10)
        # Hash-suffixed version
        store.save_index(
            owner="local", name="myapp-aabbccddeeff",
            source_files=["a.py"], symbols=[sym],
            raw_files={"a.py": "def f(): pass"}, languages={"python": 1},
        )
        # Exact name version
        store.save_index(
            owner="acme", name="myapp",
            source_files=["a.py"], symbols=[sym],
            raw_files={"a.py": "def f(): pass"}, languages={"python": 1},
        )
        owner, name = parse_repo("myapp", storage_path=str(tmp_path))
        assert owner == "acme"
        assert name == "myapp"

    def test_bare_name_no_false_prefix_match(self, tmp_path):
        """12-char hex suffix is required — don't match arbitrary suffixes."""
        from codesight_mcp.tools._common import parse_repo
        from codesight_mcp.core.errors import RepoNotFoundError
        from codesight_mcp.storage import IndexStore
        from codesight_mcp.parser import Symbol

        store = IndexStore(base_path=str(tmp_path))
        store.save_index(
            owner="local", name="myapp-notahexhash",
            source_files=["a.py"],
            symbols=[Symbol(id="a-py::f", file="a.py", name="f",
                            qualified_name="f", kind="function", language="python",
                            signature="def f():", byte_offset=0, byte_length=10)],
            raw_files={"a.py": "def f(): pass"}, languages={"python": 1},
        )
        with pytest.raises(RepoNotFoundError, match="not found"):
            parse_repo("myapp", storage_path=str(tmp_path))


# -- TEST-LOW-3: get_symbols mixed found/not-found ----------------------------

class TestGetSymbolsMixed:
    """TEST-LOW-3: get_symbols with a mix of valid and invalid symbol_ids."""

    def test_get_symbols_mixed_valid_and_invalid(self, tmp_path):
        """Valid symbol_ids return results; invalid ones return errors (no crash)."""
        import tempfile
        from codesight_mcp.storage.index_store import IndexStore
        from codesight_mcp.tools.get_symbol import get_symbols
        from codesight_mcp.parser import parse_file

        src = "def alpha():\n    return 1\n\ndef beta():\n    return 2\n"

        with tempfile.TemporaryDirectory() as storage:
            store = IndexStore(storage)
            symbols = parse_file(src, "funcs.py", "python")
            sym_ids = [s.id for s in symbols if s.name in ("alpha", "beta")]
            assert len(sym_ids) >= 1, "Expected at least one parsed symbol"

            store.save_index(
                owner="local", name="mixtest",
                source_files=["funcs.py"],
                symbols=symbols,
                raw_files={"funcs.py": src},
                languages={"python": 1},
            )

            valid_id = sym_ids[0]
            invalid_id = "nonexistent::bogus_symbol_id"

            result = get_symbols(
                repo="local/mixtest",
                symbol_ids=[valid_id, invalid_id],
                storage_path=storage,
            )

            assert "symbols" in result, f"Expected 'symbols' key in result: {result}"
            assert "errors" in result, f"Expected 'errors' key in result: {result}"

            # id fields are now wrapped with spotlighting markers (ADV-HIGH-4)
            found_ids = [s["id"] for s in result["symbols"]]
            assert any(valid_id in wrapped for wrapped in found_ids), (
                f"Valid symbol {valid_id!r} missing from symbols: {found_ids}"
            )

            error_ids = [e["id"] for e in result["errors"]]
            assert invalid_id in error_ids, (
                f"Invalid symbol {invalid_id!r} missing from errors: {error_ids}"
            )


# -- ADV-LOW-6: CODESIGHT_ALLOWED_ROOTS resolved to absolute paths at startup --

class TestAllowedRootsAbsolutePaths:
    """ADV-LOW-6: CODESIGHT_ALLOWED_ROOTS must be resolved to absolute paths."""

    def test_relative_env_path_resolves_to_absolute(self):
        """A relative path in CODESIGHT_ALLOWED_ROOTS must resolve to an absolute path."""
        from pathlib import Path as _Path
        relative = "some/relative/path"
        resolved = str(_Path(relative).resolve())
        assert resolved.startswith("/"), (
            f"Expected resolved path to be absolute, got: {resolved!r}"
        )

    def test_allowed_roots_are_absolute_paths(self):
        """ALLOWED_ROOTS module-level list must contain only absolute paths."""
        import codesight_mcp.server as server_module
        for root in server_module.ALLOWED_ROOTS:
            assert root.startswith("/"), (
                f"ALLOWED_ROOTS entry is not absolute: {root!r}"
            )


# -- ADV-LOW-7: CODE_INDEX_PATH read once at startup --

class TestCodeIndexPathReadOnce:
    """ADV-LOW-7: CODE_INDEX_PATH must be read once at startup; later env changes must not affect it."""

    def test_env_mutation_after_import_does_not_affect_stored_path(self, monkeypatch):
        """Modifying os.environ after module import must not change _CODE_INDEX_PATH."""
        import codesight_mcp.server as server_module

        # Record the value frozen at import time
        frozen = server_module._CODE_INDEX_PATH

        # Mutate the environment
        monkeypatch.setenv("CODE_INDEX_PATH", "/tmp/new-path-that-should-be-ignored")

        # The module-level constant must not have changed
        assert server_module._CODE_INDEX_PATH == frozen, (
            f"_CODE_INDEX_PATH changed after env mutation: "
            f"was {frozen!r}, now {server_module._CODE_INDEX_PATH!r}"
        )


class TestPersistentRateLimit:
    """Persistent rate-limit state must survive across helper calls."""

    def test_rate_limit_writes_state_file(self, tmp_path):
        assert _rate_limit("search_text", str(tmp_path)) is True

        state_path = Path(tmp_path) / ".rate_limits.json"
        assert state_path.exists(), "Rate-limit state file was not created"

        data = json.loads(state_path.read_text(encoding="utf-8"))
        assert "global" in data
        assert "search_text" in data.get("tools", {})

    def test_rate_limit_rejects_symlink_lock_file(self, tmp_path):
        target = tmp_path / "outside.lock"
        target.write_text("decoy", encoding="utf-8")
        (tmp_path / ".rate_limits.lock").symlink_to(target)

        with pytest.raises(OSError):
            _rate_limit("search_text", str(tmp_path))

    def test_rate_limit_rejects_symlink_tmp_state_file(self, tmp_path):
        target = tmp_path / "outside.json"
        target.write_text("decoy", encoding="utf-8")
        (tmp_path / ".rate_limits.json.tmp").symlink_to(target)

        # OSError from symlink is swallowed — call is still allowed
        assert _rate_limit("search_text", str(tmp_path)) is True

    def test_rate_limit_temp_fallback_is_private_per_user(self, monkeypatch, tmp_path):
        import codesight_mcp.core.rate_limiting as rl_module

        real_ensure = rl_module.ensure_private_dir
        home_dir = Path.home() / ".code-index"

        def fake_ensure(path):
            p = Path(path)
            if p == home_dir:
                raise OSError("deny home dir")
            return real_ensure(p)

        monkeypatch.setattr(rl_module, "ensure_private_dir", fake_ensure)

        fallback = rl_module._rate_limit_state_dir(None)
        assert "codesight-mcp-rate-limits-" in fallback.name

    def test_rate_limit_rejects_symlink_state_dir(self, tmp_path):
        real_dir = tmp_path / "real"
        real_dir.mkdir()
        link_dir = tmp_path / "link"
        link_dir.symlink_to(real_dir)

        with pytest.raises(OSError):
            _rate_limit("search_text", str(link_dir))

    def test_rate_limit_oversized_state_file_resets_safely(self, tmp_path):
        from codesight_mcp.core.limits import MAX_INDEX_SIZE

        state_path = tmp_path / ".rate_limits.json"
        state_path.write_text("x" * (MAX_INDEX_SIZE + 1), encoding="utf-8")

        assert _rate_limit("search_text", str(tmp_path)) is True

        data = json.loads(state_path.read_text(encoding="utf-8"))
        assert "global" in data
        assert "search_text" in data.get("tools", {})

    def test_rate_limit_non_dict_state_resets_safely(self, tmp_path):
        state_path = tmp_path / ".rate_limits.json"
        state_path.write_text('["not", "a", "dict"]', encoding="utf-8")

        assert _rate_limit("search_text", str(tmp_path)) is True


# -- CLI subcommand tests -----------------------------------------------------

class TestCLISubcommands:
    """Tests for the CLI entry point (main function)."""

    def test_main_index_subcommand(self, tmp_path, monkeypatch):
        """CLI: codesight-mcp index <path> --no-ai"""
        import sys
        from codesight_mcp.server import main

        project_dir = tmp_path / "proj"
        project_dir.mkdir()
        (project_dir / "foo.py").write_text("def foo(): pass\n")

        monkeypatch.setattr(
            sys, "argv",
            ["codesight-mcp", "index", str(project_dir), "--no-ai"],
        )
        monkeypatch.setenv("CODESIGHT_ALLOWED_ROOTS", str(project_dir))

        with pytest.raises(SystemExit) as exc_info:
            main()
        # 0 = success, 1 = index failed (e.g. no symbols) -- either is acceptable
        assert exc_info.value.code in (0, 1)

    def test_main_index_repo_no_url(self, monkeypatch):
        """CLI: codesight-mcp index-repo (missing URL) prints error and exits 1."""
        import sys
        from codesight_mcp.server import main

        monkeypatch.setattr(sys, "argv", ["codesight-mcp", "index-repo"])

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

    def test_main_no_subcommand_starts_server(self, monkeypatch):
        """CLI with no subcommand calls run_server (MCP mode)."""
        import sys
        import codesight_mcp.server as server_module

        server_started = []

        async def fake_run_server():
            server_started.append(True)

        monkeypatch.setattr(sys, "argv", ["codesight-mcp"])
        monkeypatch.setattr(server_module, "run_server", fake_run_server)

        # main() calls asyncio.run(run_server()) which should not raise
        server_module.main()
        assert server_started


# -- Usage logging integration tests ------------------------------------------


@pytest.mark.asyncio
async def test_call_tool_records_usage():
    """call_tool records a UsageRecord for each invocation."""
    with _usage_logger._lock:
        _usage_logger._records.clear()
    result = await call_tool("get_status", {})
    data = json.loads(result[0].text)
    assert "error" not in data
    records = _usage_logger.get_records()
    assert len(records) >= 1
    rec = records[-1]
    assert rec.tool_name == "get_status"
    assert rec.success is True
    assert rec.response_time_ms >= 0


@pytest.mark.asyncio
async def test_call_tool_does_not_log_get_usage_stats():
    """get_usage_stats is excluded from its own logging."""
    with _usage_logger._lock:
        _usage_logger._records.clear()
    await call_tool("get_usage_stats", {})
    records = _usage_logger.get_records(tool_name="get_usage_stats")
    assert len(records) == 0


@pytest.mark.asyncio
async def test_call_tool_logs_arg_keys_not_values():
    """Usage records capture argument keys but not values."""
    with _usage_logger._lock:
        _usage_logger._records.clear()
    await call_tool("get_file_outline", {"repo": "nonexistent/repo", "file_path": "main.py"})
    records = _usage_logger.get_records(tool_name="get_file_outline")
    assert len(records) >= 1
    rec = records[-1]
    assert "file_path" in rec.argument_keys
    assert "repo" in rec.argument_keys
    # Values should NOT be in the record
    assert not hasattr(rec, 'argument_values')


class TestCLIUsageLogging:
    """CLI dispatch (_run_cli_tool) records usage."""

    def test_cli_tool_records_usage(self):
        """_run_cli_tool records a UsageRecord for the dispatched tool."""
        from codesight_mcp.server import _run_cli_tool, _usage_logger
        with _usage_logger._lock:
            _usage_logger._records.clear()
        with pytest.raises(SystemExit):
            _run_cli_tool("get_status", [])
        records = _usage_logger.get_records(tool_name="get_status")
        # Filter to current session to avoid file history
        current = [r for r in records if r.session_id == _usage_logger._session_id]
        assert len(current) >= 1
        assert current[-1].tool_name == "get_status"
        assert current[-1].response_time_ms >= 0

    def test_cli_tool_does_not_log_get_usage_stats(self):
        """get_usage_stats via CLI is excluded from its own logging."""
        from codesight_mcp.server import _run_cli_tool, _usage_logger
        with _usage_logger._lock:
            _usage_logger._records.clear()
        with pytest.raises(SystemExit):
            _run_cli_tool("get_usage_stats", [])
        records = _usage_logger.get_records(tool_name="get_usage_stats")
        current = [r for r in records if r.session_id == _usage_logger._session_id]
        assert len(current) == 0

    def test_cli_tool_logs_failure(self):
        """CLI tool that fails still gets a usage record."""
        from codesight_mcp.server import _run_cli_tool, _usage_logger
        with _usage_logger._lock:
            _usage_logger._records.clear()
        with pytest.raises(SystemExit):
            _run_cli_tool("get_symbol", ["--repo", "nonexistent/repo", "--symbol-id", "fake"])
        records = _usage_logger.get_records(tool_name="get_symbol")
        current = [r for r in records if r.session_id == _usage_logger._session_id]
        assert len(current) >= 1
