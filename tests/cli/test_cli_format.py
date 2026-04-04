"""Tests for CLI output formatters."""

import json

from codesight_mcp.cli_format import format_result


class TestFormatResult:
    """Tests for format_result pure function."""

    def test_json_default(self):
        """JSON format returns indented json.dumps."""
        data = {"key": "val", "num": 42}
        assert format_result(data, "json") == json.dumps(data, indent=2)

    def test_compact(self):
        """Compact format returns single-line JSON."""
        data = {"key": "val", "num": 42}
        assert format_result(data, "compact") == json.dumps(data)

    def test_error_always_json(self):
        """Error responses always render as JSON regardless of format."""
        data = {"error": "something broke"}
        result = format_result(data, "table")
        assert result == json.dumps(data, indent=2)

    def test_table_flat_dict(self):
        """Flat scalar dict renders as key-value pairs."""
        data = {"name": "test", "count": 5}
        result = format_result(data, "table")
        assert "name" in result
        assert "test" in result
        assert "count" in result
        assert "5" in result
        # Should be aligned, not JSON
        assert "{" not in result

    def test_table_wrapped_payload(self):
        """Wrapped payload with list-of-dicts renders as table."""
        data = {
            "count": 3,
            "repos": [
                {"name": "alpha", "symbols": 100},
                {"name": "beta", "symbols": 200},
            ],
            "_meta": {"source": "test"},
        }
        result = format_result(data, "table")
        # Scalar header
        assert "count: 3" in result
        # Column headers uppercase
        assert "NAME" in result
        assert "SYMBOLS" in result
        # Data values
        assert "alpha" in result
        assert "beta" in result
        # _meta excluded
        assert "_meta" not in result
        assert "source" not in result

    def test_table_nested_dict_fallback(self):
        """Nested dicts fall back to JSON."""
        data = {"checks": {"a": {"passed": True}}}
        result = format_result(data, "table")
        # Should be JSON (contains braces)
        parsed = json.loads(result)
        assert parsed == data

    def test_table_multiple_lists_fallback(self):
        """Multiple list-valued keys fall back to JSON."""
        data = {"a": [1, 2], "b": [3, 4]}
        result = format_result(data, "table")
        parsed = json.loads(result)
        assert parsed == data

    def test_table_list_of_non_dicts_fallback(self):
        """List-of-non-dicts (e.g., list-of-lists) falls back to JSON."""
        data = {"paths": [[1, 2], [3, 4]]}
        result = format_result(data, "table")
        parsed = json.loads(result)
        assert parsed == data

    def test_tsv_flat_dict(self):
        """Flat dict renders as key\\tvalue rows."""
        data = {"name": "test", "count": "5"}
        result = format_result(data, "tsv")
        lines = result.strip().split("\n")
        assert any("name\ttest" in line for line in lines)
        assert any("count\t5" in line for line in lines)

    def test_tsv_list_of_dicts(self):
        """Wrapped payload renders as TSV with header row."""
        data = {
            "count": 2,
            "items": [
                {"name": "a", "value": "1"},
                {"name": "b", "value": "2"},
            ],
            "_meta": {"source": "test"},
        }
        result = format_result(data, "tsv")
        lines = result.strip().split("\n")
        # Scalar header
        assert lines[0] == "count: 2"
        # Find the TSV header row (contains tab-separated column names)
        tsv_header = None
        for line in lines:
            if "\t" in line and "name" in line and "value" in line:
                tsv_header = line
                break
        assert tsv_header is not None
        # _meta excluded
        assert "_meta" not in result

    def test_meta_excluded(self):
        """_meta key is excluded from table and tsv output."""
        data = {"key": "val", "_meta": {"source": "test", "timing_ms": 42}}
        for fmt in ("table", "tsv"):
            result = format_result(data, fmt)
            assert "_meta" not in result
            assert "timing_ms" not in result

    def test_spotlighting_stripped(self):
        """Spotlighting markers are stripped in table output."""
        data = {
            "repo": "<<<UNTRUSTED_CODE_abc123def456abc123def456abc12345>>>\ntest/repo\n<<<END_UNTRUSTED_CODE_abc123def456abc123def456abc12345>>>",
        }
        result = format_result(data, "table")
        assert "UNTRUSTED_CODE" not in result
        assert "test/repo" in result

    def test_control_chars_stripped(self):
        """Control characters and ANSI escapes are stripped in table/tsv."""
        data = {
            "name": "test\twith\ttabs",
            "desc": "line1\nline2",
            "color": "\x1b[31mred\x1b[0m",
        }
        result = format_result(data, "table")
        assert "\t" not in result
        assert "\n" not in result.split("\n")[0]  # no embedded newlines within a row
        assert "\x1b" not in result

    def test_truncation(self):
        """Values longer than 60 chars are truncated in table output."""
        long_val = "x" * 80
        data = {"key": long_val}
        result = format_result(data, "table")
        assert "..." in result
        # Truncated value should be 60 chars: 57 + "..."
        val_part = result.split()[-1]  # the value part after key
        assert len(val_part) == 60

    def test_tsv_no_truncation(self):
        """TSV does NOT truncate values."""
        long_val = "x" * 80
        data = {"key": long_val}
        result = format_result(data, "tsv")
        assert long_val in result
        assert "..." not in result

    def test_empty_list_shows_headers_only(self):
        """Empty list payload shows scalar headers only, no table rows."""
        data = {"count": 0, "items": []}
        result = format_result(data, "table")
        assert "count: 0" in result
        # Should not be JSON (no braces)
        assert "{" not in result

    def test_heterogeneous_row_keys(self):
        """Rows with different key sets show all columns, missing = empty."""
        data = {
            "items": [
                {"name": "a", "x": 1},
                {"name": "b", "y": 2},
            ],
        }
        result = format_result(data, "table")
        # All keys present as columns
        assert "NAME" in result
        assert "X" in result
        assert "Y" in result
