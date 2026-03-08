"""Tests for ADV-MED-3, ADV-MED-6, ADV-MED-10, ADV-LOW-5 security findings."""

import asyncio
import logging
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from codesight_mcp.discovery import _RedactAuthFilter
from codesight_mcp.tools.search_symbols import search_symbols
from codesight_mcp.tools.index_folder import index_folder
from codesight_mcp.tools.index_repo import index_repo
from codesight_mcp.tools.get_symbol import get_symbol
from codesight_mcp.storage.index_store import IndexStore
from codesight_mcp.parser.symbols import Symbol


# ---------------------------------------------------------------------------
# Helper: build a minimal indexed store with one symbol
# ---------------------------------------------------------------------------

def _make_store(tmp: str) -> IndexStore:
    """Create a minimal index with a single symbol."""
    symbols = [Symbol(
        id="src/mod.py::myfunc#function",
        file="src/mod.py",
        name="myfunc",
        qualified_name="myfunc",
        kind="function",
        language="python",
        signature="def myfunc():",
        docstring="",
        summary="my function",
        decorators=[],
        keywords=[],
        parent=None,
        line=1, end_line=3,
        byte_offset=0, byte_length=30,
        content_hash="c" * 64,
    )]
    store = IndexStore(tmp)
    content_dir = Path(tmp) / "owner__myrepo"
    content_dir.mkdir(parents=True, exist_ok=True)
    src_dir = content_dir / "src"
    src_dir.mkdir()
    (src_dir / "mod.py").write_text("def myfunc():\n    pass\n")
    store.save_index(
        owner="owner", name="myrepo",
        source_files=["src/mod.py"],
        symbols=symbols,
        raw_files={"src/mod.py": "def myfunc():\n    pass\n"},
        languages={"python": 1},
    )
    return store


# ---------------------------------------------------------------------------
# ADV-MED-3: kind and language validation in search_symbols
# ---------------------------------------------------------------------------

class TestSearchSymbolsKindValidation:
    """ADV-MED-3: invalid kind must return an error, not silently empty results."""

    def test_invalid_kind_returns_error(self):
        """search_symbols with kind='INVALID' must return an error dict."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_store(tmp)
            result = search_symbols(
                repo="owner/myrepo",
                query="myfunc",
                kind="INVALID",
                storage_path=tmp,
            )
            assert "error" in result, (
                f"Expected error for invalid kind, got: {result}"
            )
            assert "Invalid kind" in result["error"]

    def test_invalid_kind_result_count_zero(self):
        """Error response for invalid kind must have result_count=0."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_store(tmp)
            result = search_symbols(
                repo="owner/myrepo",
                query="myfunc",
                kind="BADKIND",
                storage_path=tmp,
            )
            assert result.get("result_count", 0) == 0

    def test_valid_kind_function_works(self):
        """search_symbols with kind='function' must not return an error."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_store(tmp)
            result = search_symbols(
                repo="owner/myrepo",
                query="myfunc",
                kind="function",
                storage_path=tmp,
            )
            assert "error" not in result or "Invalid kind" not in result.get("error", "")

    def test_invalid_language_returns_error(self):
        """search_symbols with language='cobol' must return an error dict."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_store(tmp)
            result = search_symbols(
                repo="owner/myrepo",
                query="myfunc",
                language="cobol",
                storage_path=tmp,
            )
            assert "error" in result, (
                f"Expected error for invalid language, got: {result}"
            )
            assert "Invalid language" in result["error"]

    def test_valid_language_python_works(self):
        """search_symbols with language='python' must not return an invalid-language error."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_store(tmp)
            result = search_symbols(
                repo="owner/myrepo",
                query="myfunc",
                language="python",
                storage_path=tmp,
            )
            assert "Invalid language" not in result.get("error", "")

    def test_none_kind_allowed(self):
        """search_symbols with kind=None (default) must succeed."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_store(tmp)
            result = search_symbols(
                repo="owner/myrepo",
                query="myfunc",
                kind=None,
                storage_path=tmp,
            )
            assert "Invalid kind" not in result.get("error", "")


# ---------------------------------------------------------------------------
# ADV-MED-6: parse failure warnings must not leak file paths
# ---------------------------------------------------------------------------

class TestIndexFolderParsedWarningsNoPath:
    """ADV-MED-6: index_folder parse-failure warnings must use aggregate counts."""

    def test_parse_failure_warning_has_count_not_path(self, tmp_path):
        """When a file fails to parse, warning must mention count, not the path."""
        storage = tmp_path / "_storage"

        # Write a valid Python file so indexing doesn't fail entirely
        (tmp_path / "good.py").write_text("def ok():\n    pass\n")
        # Write a file that triggers a parse exception via monkeypatching
        (tmp_path / "bad.py").write_text("def broken():\n    pass\n")

        with patch("codesight_mcp.tools._indexing_common.parse_file") as mock_parse:
            def side_effect(content, path, language):
                if "bad.py" in path:
                    raise RuntimeError("simulated parse error")
                # Return minimal symbol list for good file
                from codesight_mcp.parser.symbols import Symbol
                return [Symbol(
                    id=f"{path}::ok#function",
                    file=path, name="ok", qualified_name="ok",
                    kind="function", language="python",
                    signature="def ok():", docstring="", summary="",
                    decorators=[], keywords=[], parent=None,
                    line=1, end_line=2, byte_offset=0, byte_length=20,
                    content_hash="a" * 64,
                )]
            mock_parse.side_effect = side_effect

            result = index_folder(
                path=str(tmp_path),
                use_ai_summaries=False,
                storage_path=str(storage),
                allowed_roots=[str(tmp_path)],
            )

        assert result.get("success") is True, f"Expected success, got: {result}"
        warnings = result.get("warnings", [])
        # At least one warning about parse failure
        parse_warnings = [w for w in warnings if "failed to parse" in w.lower()]
        assert len(parse_warnings) > 0, (
            f"Expected a parse-failure warning, got warnings: {warnings}"
        )
        # Warning must NOT contain the specific file path
        for w in parse_warnings:
            assert "bad.py" not in w, (
                f"Warning leaked file path: {w!r}"
            )
        # Warning must contain a count (digit followed by "file")
        import re
        for w in parse_warnings:
            assert re.search(r"\d+\s+file", w), (
                f"Warning must contain a count, got: {w!r}"
            )


class TestIndexRepoParsedWarningsNoPath:
    """ADV-MED-6: index_repo parse-failure warnings must use aggregate counts."""

    def test_parse_failure_warning_has_count_not_path(self):
        """When a repo file fails to parse, the warning must not contain the path."""
        from unittest.mock import AsyncMock, patch
        import asyncio

        tree_entries = [
            {"path": "good.py", "type": "blob", "size": 50},
            {"path": "bad.py", "type": "blob", "size": 50},
        ]

        async def fake_fetch_tree(owner, repo, token):
            return tree_entries

        async def fake_fetch_file(owner, repo, path, token):
            return "def ok():\n    pass\n"

        async def fake_fetch_gitignore(owner, repo, token):
            return ""

        with (
            patch("codesight_mcp.tools.index_repo.fetch_repo_tree", new=fake_fetch_tree),
            patch("codesight_mcp.tools.index_repo.fetch_file_content", new=fake_fetch_file),
            patch("codesight_mcp.tools.index_repo.fetch_gitignore", new=fake_fetch_gitignore),
            patch("codesight_mcp.tools._indexing_common.parse_file") as mock_parse,
            patch("codesight_mcp.tools._indexing_common.summarize_symbols", side_effect=lambda syms, use_ai: syms),
            patch("codesight_mcp.tools._indexing_common.IndexStore") as mock_store_cls,
        ):
            # Make parse raise for bad.py, succeed for good.py
            from codesight_mcp.parser.symbols import Symbol
            def side_effect(content, path, language):
                if "bad.py" in path:
                    raise RuntimeError("simulated parse error")
                return [Symbol(
                    id=f"{path}::ok#function",
                    file=path, name="ok", qualified_name="ok",
                    kind="function", language="python",
                    signature="def ok():", docstring="", summary="",
                    decorators=[], keywords=[], parent=None,
                    line=1, end_line=2, byte_offset=0, byte_length=20,
                    content_hash="a" * 64,
                )]
            mock_parse.side_effect = side_effect

            # Mock the IndexStore so we don't write files
            mock_store = MagicMock()
            mock_index = MagicMock()
            mock_index.indexed_at = "2026-01-01T00:00:00"
            mock_store.load_index.return_value = mock_index
            mock_store_cls.return_value = mock_store

            result = asyncio.run(index_repo(
                url="https://github.com/testowner/testrepo",
                use_ai_summaries=False,
            ))

        assert result.get("success") is True, f"Expected success, got: {result}"
        warnings = result.get("warnings", [])
        parse_warnings = [w for w in warnings if "failed to parse" in w.lower()]
        assert len(parse_warnings) > 0, (
            f"Expected parse-failure warning, got: {warnings}"
        )
        for w in parse_warnings:
            assert "bad.py" not in w, f"Warning leaked file path: {w!r}"
        import re
        for w in parse_warnings:
            assert re.search(r"\d+\s+file", w), (
                f"Warning must contain a count, got: {w!r}"
            )


# ---------------------------------------------------------------------------
# ADV-MED-10: _RedactAuthFilter must suppress auth records at all log levels
# ---------------------------------------------------------------------------

class TestRedactAuthFilterAllLevels:
    """ADV-MED-10: _RedactAuthFilter must suppress auth-containing records at WARNING+."""

    def _make_record(self, level: int, msg: str, name: str = "httpx.client") -> logging.LogRecord:
        record = logging.LogRecord(
            name=name,
            level=level,
            pathname="",
            lineno=0,
            msg=msg,
            args=(),
            exc_info=None,
        )
        return record

    def test_debug_auth_record_suppressed(self):
        """DEBUG record with Authorization header must be suppressed."""
        filt = _RedactAuthFilter()
        record = self._make_record(logging.DEBUG, "Authorization: Bearer secret123")
        assert filt.filter(record) is False

    def test_warning_auth_record_suppressed(self):
        """WARNING record with Authorization header must be suppressed."""
        filt = _RedactAuthFilter()
        record = self._make_record(logging.WARNING, "Authorization: Bearer secret123")
        assert filt.filter(record) is False, (
            "WARNING-level auth record must be suppressed"
        )

    def test_error_auth_record_suppressed(self):
        """ERROR record with Authorization header must be suppressed."""
        filt = _RedactAuthFilter()
        record = self._make_record(logging.ERROR, "request header: Authorization: Bearer tok")
        assert filt.filter(record) is False, (
            "ERROR-level auth record must be suppressed"
        )

    def test_info_auth_record_suppressed(self):
        """INFO record with Authorization header must be suppressed."""
        filt = _RedactAuthFilter()
        record = self._make_record(logging.INFO, "Sending header Authorization: Bearer xyz")
        assert filt.filter(record) is False, (
            "INFO-level auth record must be suppressed"
        )

    def test_warning_no_auth_not_suppressed(self):
        """WARNING record without auth header must pass through."""
        filt = _RedactAuthFilter()
        record = self._make_record(logging.WARNING, "Connection timeout to api.github.com")
        assert filt.filter(record) is True

    def test_non_httpx_auth_not_suppressed(self):
        """Auth record from a non-httpx logger must not be suppressed."""
        filt = _RedactAuthFilter()
        record = self._make_record(logging.WARNING, "Authorization: Bearer secret123", name="myapp")
        assert filt.filter(record) is True

    def test_auth_case_insensitive(self):
        """Filter must catch mixed-case 'AUTHORIZATION' as well."""
        filt = _RedactAuthFilter()
        record = self._make_record(logging.WARNING, "AUTHORIZATION: Bearer secret")
        assert filt.filter(record) is False


# ---------------------------------------------------------------------------
# ADV-LOW-5: get_symbol context lines must survive OSError gracefully
# ---------------------------------------------------------------------------

class TestGetSymbolContextOSError:
    """ADV-LOW-5: OSError in context line reading must not crash get_symbol."""

    def test_oserror_in_safe_read_file_returns_no_context(self):
        """When safe_read_file raises OSError, get_symbol must succeed without context fields."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_store(tmp)

            with patch(
                "codesight_mcp.tools.get_symbol.safe_read_file",
                side_effect=OSError("simulated disk error"),
            ):
                result = get_symbol(
                    repo="owner/myrepo",
                    symbol_id="src/mod.py::myfunc#function",
                    context_lines=2,
                    storage_path=tmp,
                )

            assert "error" not in result, (
                f"get_symbol must not return an error on OSError in context: {result}"
            )
            # context fields must be absent (OSError skipped gracefully)
            assert "context_before" not in result, (
                "context_before must not be present when safe_read_file raises OSError"
            )
            assert "context_after" not in result, (
                "context_after must not be present when safe_read_file raises OSError"
            )
            # Core fields must still be present
            assert "source" in result
            assert "name" in result

    def test_ioerror_in_safe_read_file_returns_no_context(self):
        """When safe_read_file raises IOError (alias for OSError), context is skipped."""
        with tempfile.TemporaryDirectory() as tmp:
            _make_store(tmp)

            with patch(
                "codesight_mcp.tools.get_symbol.safe_read_file",
                side_effect=IOError("simulated io error"),
            ):
                result = get_symbol(
                    repo="owner/myrepo",
                    symbol_id="src/mod.py::myfunc#function",
                    context_lines=2,
                    storage_path=tmp,
                )

            assert "error" not in result
            assert "context_before" not in result
            assert "context_after" not in result
