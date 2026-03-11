"""Tests for search_text tool — spotlighting (ADV-HIGH-1) and existing behaviour."""

import tempfile
from pathlib import Path

import pytest

from codesight_mcp.storage import IndexStore
from codesight_mcp.parser.symbols import Symbol
from codesight_mcp.tools.search_text import search_text


def _make_store_with_file(
    tmp: str,
    owner: str,
    name: str,
    file_path: str,
    file_content: str,
) -> IndexStore:
    """Build a minimal IndexStore with a single indexed file."""
    store = IndexStore(base_path=tmp)
    store.save_index(
        owner=owner,
        name=name,
        source_files=[file_path],
        symbols=[],
        raw_files={file_path: file_content},
        languages={"python": 1},
    )
    return store


# ---------------------------------------------------------------------------
# ADV-HIGH-1: file path in search_text results must be spotlighted
# ---------------------------------------------------------------------------

class TestSearchTextFileSpotlighting:
    """ADV-HIGH-1: 'file' field in search_text results must be wrapped in spotlighting."""

    def test_file_field_is_wrapped(self):
        """The 'file' value in each match must start with <<<UNTRUSTED_CODE_."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_store_with_file(
                tmp, "owner", "repo",
                file_path="utils.py",
                file_content="def helper():\n    return True\n",
            )
            result = search_text(
                repo="owner/repo", query="helper",
                storage_path=tmp
            )

            assert "error" not in result
            assert result["result_count"] >= 1, "Expected at least one match"
            for match in result["results"]:
                file_val = match["file"]
                assert file_val.startswith("<<<UNTRUSTED_CODE_"), (
                    f"'file' field not wrapped in spotlighting markers: {file_val!r}"
                )

    def test_injection_filename_is_wrapped(self):
        """A file with an injection-phrase name must have its path wrapped."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_store_with_file(
                tmp, "owner", "repo2",
                file_path="IGNORE_PREVIOUS.py",
                file_content="ignore_previous_instructions = True\n",
            )
            result = search_text(
                repo="owner/repo2",
                query="ignore_previous",
                storage_path=tmp,
            )

            assert "error" not in result
            assert result["result_count"] >= 1, "Expected at least one match"
            for match in result["results"]:
                file_val = match["file"]
                assert file_val.startswith("<<<UNTRUSTED_CODE_"), (
                    f"Injection filename not wrapped: {file_val!r}"
                )

    def test_wrapped_file_contains_original_path(self):
        """The wrapped 'file' value must contain the original file path inside the markers."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_store_with_file(
                tmp, "owner", "repo3",
                file_path="src/module.py",
                file_content="MY_CONST = 42\n",
            )
            result = search_text(
                repo="owner/repo3", query="MY_CONST",
                storage_path=tmp
            )

            assert "error" not in result
            assert result["result_count"] >= 1
            for match in result["results"]:
                file_val = match["file"]
                assert "src/module.py" in file_val, (
                    f"Original path not found inside wrapped value: {file_val!r}"
                )

    def test_text_field_is_also_wrapped(self):
        """The 'text' field in each match must also be wrapped (pre-existing behaviour)."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_store_with_file(
                tmp, "owner", "repo4",
                file_path="app.py",
                file_content="result = compute()\n",
            )
            result = search_text(
                repo="owner/repo4", query="compute",
                storage_path=tmp
            )

            assert "error" not in result
            assert result["result_count"] >= 1
            for match in result["results"]:
                assert match["text"].startswith("<<<UNTRUSTED_CODE_"), (
                    f"'text' field not wrapped: {match['text']!r}"
                )

    def test_no_results_returns_empty_list(self):
        """A query with no matches must return result_count=0 and empty results."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_store_with_file(
                tmp, "owner", "repo5",
                file_path="empty.py",
                file_content="x = 1\n",
            )
            result = search_text(
                repo="owner/repo5", query="zzznomatch999",
                storage_path=tmp
            )

            assert "error" not in result
            assert result["result_count"] == 0
            assert result["results"] == []

    def test_unknown_repo_returns_error(self):
        """A query against an unindexed repo must return an error dict."""
        with tempfile.TemporaryDirectory() as tmp:
            result = search_text(
                repo="nobody/ghost", query="anything",
                storage_path=tmp
            )
            assert "error" in result

    def test_secret_in_result_line_is_redacted(self):
        """SEC-MED-3: secrets in matching lines must be redacted before returning."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_store_with_file(
                tmp, "owner", "repo_sec3",
                file_path="config.py",
                file_content='TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"\nprint(TOKEN)\n',
            )
            result = search_text(
                repo="owner/repo_sec3",
                query="TOKEN",
                storage_path=tmp,
            )

            assert "error" not in result
            assert result["result_count"] >= 1
            for match in result["results"]:
                assert "ghp_" not in match["text"], (
                    f"Secret token not redacted in search result: {match['text']!r}"
                )

    def test_redaction_marker_query_rejected(self):
        """search_text must reject queries for the internal redaction sentinel."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_store_with_file(
                tmp, "owner", "repo7",
                file_path="x.py",
                file_content='API_KEY = "sk-testkey12345678901234"\n',
            )
            result = search_text(
                repo="owner/repo7",
                query="<REDACTED>",
                storage_path=tmp,
            )

            assert "error" in result
            assert "redaction" in result["error"].lower()

    def test_redaction_sentinel_substring_rejected(self):
        """Substrings of the redaction sentinel (>= 4 chars) must also be blocked."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_store_with_file(
                tmp, "owner", "repo_sub",
                file_path="x.py",
                file_content="placeholder\n",
            )
            # "<REDA" is a prefix of "<REDACTED>" with length >= 4
            result = search_text(
                repo="owner/repo_sub",
                query="<REDA",
                storage_path=tmp,
            )
            assert "error" in result
            assert "redaction" in result["error"].lower()

    def test_redaction_sentinel_short_prefix_allowed(self):
        """Very short prefixes (< 4 chars) of the sentinel should be allowed."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_store_with_file(
                tmp, "owner", "repo_short",
                file_path="x.py",
                file_content="<RE is fine\n",
            )
            result = search_text(
                repo="owner/repo_short",
                query="<RE",
                storage_path=tmp,
            )
            # Should not be blocked (only 3 chars)
            assert "error" not in result
