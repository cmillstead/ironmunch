"""CLI dispatch tests -- _parse_cli_args, _run_cli_tool, and main() coverage.

RC-004: AEGIS remediation for near-zero CLI dispatch test coverage.
"""

import json
import os
import subprocess
import sys

import pytest

import codesight_mcp.server as server_mod
from codesight_mcp.server import (
    _parse_cli_args,
    _run_cli_tool,
    _usage_logger,
)
from codesight_mcp.tools.registry import get_all_specs


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_search_symbols_schema() -> dict:
    """Return the input_schema for search_symbols (has string, int, bool params)."""
    return get_all_specs()["search_symbols"].input_schema


# ---------------------------------------------------------------------------
# _parse_cli_args tests
# ---------------------------------------------------------------------------


class TestParseCliArgs:
    """Tests for _parse_cli_args argument parsing."""

    def test_parse_string_argument(self):
        """Parse --repo my-repo resolves to repo key with string value."""
        schema = _get_search_symbols_schema()
        result = _parse_cli_args(["--repo", "my-repo"], schema)
        assert result == {"repo": "my-repo"}

    def test_parse_integer_argument(self):
        """Parse --max-results 10 resolves to integer 10."""
        schema = _get_search_symbols_schema()
        result = _parse_cli_args(["--max-results", "10"], schema)
        assert result == {"max_results": 10}

    def test_parse_boolean_flag_standalone(self):
        """Parse --include-graph as standalone flag resolves to True."""
        schema = get_all_specs()["get_symbol_context"].input_schema
        result = _parse_cli_args(["--include-graph"], schema)
        assert result == {"include_graph": True}

    def test_parse_boolean_flag_with_explicit_value(self):
        """Parse --include-graph false resolves to False."""
        schema = get_all_specs()["get_symbol_context"].input_schema
        result = _parse_cli_args(["--include-graph", "false"], schema)
        assert result == {"include_graph": False}

    def test_hyphenated_args_convert_to_underscores(self):
        """Hyphens in flag names are converted to underscores."""
        schema = _get_search_symbols_schema()
        result = _parse_cli_args(["--max-results", "5"], schema)
        assert "max_results" in result
        assert result["max_results"] == 5

    def test_unknown_arguments_stripped(self):
        """Unknown arguments are NOT included in the result dict."""
        schema = _get_search_symbols_schema()
        result = _parse_cli_args(
            ["--query", "hello", "--unknown-flag", "value"],
            schema,
        )
        assert "unknown_flag" not in result
        assert result == {"query": "hello"}

    def test_integer_with_invalid_value_raises_system_exit(self):
        """Non-numeric value for integer param raises SystemExit."""
        schema = _get_search_symbols_schema()
        with pytest.raises(SystemExit, match="requires an integer value"):
            _parse_cli_args(["--max-results", "abc"], schema)

    def test_integer_missing_value_raises_system_exit(self):
        """Integer param at end of argv with no value raises SystemExit."""
        schema = _get_search_symbols_schema()
        with pytest.raises(SystemExit, match="requires an integer value"):
            _parse_cli_args(["--max-results"], schema)

    def test_empty_argv_returns_empty_dict(self):
        """Empty argv produces empty dict."""
        schema = _get_search_symbols_schema()
        result = _parse_cli_args([], schema)
        assert result == {}

    def test_multiple_args_combined(self):
        """Multiple different arg types parse together correctly."""
        schema = _get_search_symbols_schema()
        result = _parse_cli_args(
            ["--repo", "my-repo", "--query", "func", "--max-results", "20"],
            schema,
        )
        assert result == {"repo": "my-repo", "query": "func", "max_results": 20}

    def test_string_arg_missing_value_skipped(self):
        """String arg at end of argv with no value is skipped (no crash)."""
        schema = _get_search_symbols_schema()
        result = _parse_cli_args(["--repo"], schema)
        # When --repo is the last arg with no value, it's skipped
        assert "repo" not in result


# ---------------------------------------------------------------------------
# _run_cli_tool tests
# ---------------------------------------------------------------------------


class TestRunCliTool:
    """Tests for _run_cli_tool dispatching."""

    def test_dispatch_known_tool_get_status(self, capsys):
        """Dispatch get_status produces valid JSON output."""
        with pytest.raises(SystemExit) as exc_info:
            _run_cli_tool("get_status", [])

        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "version" in result
        assert "repo_count" in result

    def test_dispatch_unknown_tool_exits_with_error(self, capsys):
        """Unknown tool name prints error JSON and exits with code 1."""
        with pytest.raises(SystemExit) as exc_info:
            _run_cli_tool("nonexistent_tool_xyz", [])

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "error" in result
        assert "Unknown tool" in result["error"]

    def test_usage_logging_triggered(self, capsys):
        """CLI dispatch records a usage entry for the tool call."""
        initial_records = len(_usage_logger.get_records())

        with pytest.raises(SystemExit):
            _run_cli_tool("get_status", [])

        records = _usage_logger.get_records()
        # Find the get_status record added after our call
        status_records = [
            rec for rec in records[initial_records:]
            if rec.tool_name == "get_status"
        ]
        assert len(status_records) >= 1
        assert status_records[-1].success is True

    def test_sanitize_arguments_called_truncates_long_strings(self, capsys):
        """Oversized string arguments are caught by _sanitize_arguments."""
        from codesight_mcp.core.limits import MAX_ARGUMENT_LENGTH

        long_query = "x" * (MAX_ARGUMENT_LENGTH + 1)

        with pytest.raises(SystemExit) as exc_info:
            _run_cli_tool("search_symbols", ["--query", long_query])

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "error" in result
        assert "exceeds maximum length" in result["error"]

    def test_cli_help_flag(self, capsys):
        """--help flag prints usage and exits 0."""
        with pytest.raises(SystemExit) as exc_info:
            _run_cli_tool("get_status", ["--help"])

        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "Usage:" in captured.out
        assert "get-status" in captured.out

    def test_missing_required_arg(self, capsys):
        """Tool with required args shows error when they are missing."""
        with pytest.raises(SystemExit) as exc_info:
            _run_cli_tool("search_symbols", [])

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "error" in result
        assert "Missing required" in result["error"]

    def test_sets_read_only_for_non_destructive(self, capsys):
        """Non-destructive tools set CODESIGHT_READ_ONLY env var."""
        old_val = os.environ.get("CODESIGHT_READ_ONLY")
        try:
            os.environ.pop("CODESIGHT_READ_ONLY", None)
            with pytest.raises(SystemExit):
                _run_cli_tool("get_status", [])
            assert os.environ.get("CODESIGHT_READ_ONLY") == "1"
        finally:
            if old_val is not None:
                os.environ["CODESIGHT_READ_ONLY"] = old_val
            else:
                os.environ.pop("CODESIGHT_READ_ONLY", None)


# ---------------------------------------------------------------------------
# main() integration tests -- uses real subprocess to avoid patching sys.argv
# ---------------------------------------------------------------------------

_CODESIGHT_BIN = os.path.join(
    os.path.dirname(sys.executable), "codesight-mcp"
)


class TestMainEntryPoint:
    """Integration tests for the main() entry point via real subprocess."""

    def test_tools_subcommand_lists_tools(self):
        """'tools' subcommand lists all registered tools as JSON."""
        result = subprocess.run(
            [_CODESIGHT_BIN, "tools"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        tools_list = json.loads(result.stdout)
        assert isinstance(tools_list, list)
        assert len(tools_list) == 30
        names = {tool["name"] for tool in tools_list}
        assert "get_status" in names
        assert "search_symbols" in names

    def test_tool_dispatch_via_hyphenated_name(self):
        """main() dispatches tools with hyphenated names (e.g., get-status)."""
        result = subprocess.run(
            [_CODESIGHT_BIN, "get-status"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "version" in data


# ---------------------------------------------------------------------------
# --format flag tests
# ---------------------------------------------------------------------------


class TestCliFormatFlag:
    """Tests for --format flag extraction and dispatch."""

    def test_format_flag_extracted(self, capsys):
        """--format compact produces single-line JSON output."""
        with pytest.raises(SystemExit):
            _run_cli_tool("get_status", ["--format", "compact"])
        captured = capsys.readouterr()
        # Compact = single-line JSON (no newlines in the JSON part)
        # Skip the stderr line, check stdout
        lines = captured.out.strip().split("\n")
        # Should be exactly one line of JSON
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert "version" in data

    def test_format_flag_equals_syntax(self, capsys):
        """--format=compact syntax works."""
        with pytest.raises(SystemExit):
            _run_cli_tool("get_status", ["--format=compact"])
        captured = capsys.readouterr()
        lines = captured.out.strip().split("\n")
        assert len(lines) == 1
        json.loads(lines[0])  # should parse as valid JSON

    def test_format_flag_invalid(self, capsys):
        """Invalid format value exits 1 with error."""
        with pytest.raises(SystemExit) as exc_info:
            _run_cli_tool("get_status", ["--format", "xml"])
        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "error" in result
        assert "xml" in result["error"]

    def test_format_flag_missing_value(self, capsys):
        """--format with no value exits 1 with error."""
        with pytest.raises(SystemExit) as exc_info:
            _run_cli_tool("get_status", ["--format"])
        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "error" in result
        assert "Missing" in result["error"]

    def test_format_flag_rejects_flag_value(self, capsys):
        """--format --repo rejects flag-like value."""
        with pytest.raises(SystemExit) as exc_info:
            _run_cli_tool("get_status", ["--format", "--repo"])
        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "error" in result

    def test_default_json_unchanged(self, capsys):
        """Default (no --format) produces indented JSON."""
        with pytest.raises(SystemExit):
            _run_cli_tool("get_status", [])
        captured = capsys.readouterr()
        # Default JSON is indented (multiple lines)
        lines = captured.out.strip().split("\n")
        assert len(lines) > 1
        data = json.loads(captured.out)
        assert "version" in data

    def test_help_includes_format_option(self, capsys):
        """--help output includes --format global option."""
        with pytest.raises(SystemExit):
            _run_cli_tool("get_status", ["--help"])
        captured = capsys.readouterr()
        assert "--format" in captured.out
        assert "Global options" in captured.out
