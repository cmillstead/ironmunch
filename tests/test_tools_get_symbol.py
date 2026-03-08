"""Tests for get_symbol and get_symbols tools."""

import hashlib

import pytest

from codesight_mcp.tools.get_symbol import get_symbol, get_symbols
from codesight_mcp.storage import IndexStore
from codesight_mcp.parser import Symbol


def _make_indexed_repo(tmp_path):
    """Create an index with two Python symbols for testing."""
    src = "def greet(name):\n    return f'Hello {name}'\n"
    src_hash = hashlib.sha256(src.encode("utf-8")).hexdigest()

    helper_src = "def helper():\n    pass\n"
    helper_hash = hashlib.sha256(helper_src.encode("utf-8")).hexdigest()

    full_content = src + helper_src

    symbols = [
        Symbol(
            id="app.py::greet#function",
            file="app.py",
            name="greet",
            qualified_name="greet",
            kind="function",
            language="python",
            signature="def greet(name):",
            summary="Greet someone",
            line=1, end_line=2,
            byte_offset=0, byte_length=len(src),
            content_hash=src_hash,
        ),
        Symbol(
            id="app.py::helper#function",
            file="app.py",
            name="helper",
            qualified_name="helper",
            kind="function",
            language="python",
            signature="def helper():",
            summary="A helper",
            line=3, end_line=4,
            byte_offset=len(src), byte_length=len(helper_src),
            content_hash=helper_hash,
        ),
    ]

    store = IndexStore(base_path=str(tmp_path))

    # Create content directory with the source file
    content_dir = tmp_path / "local__testapp"
    content_dir.mkdir(parents=True, exist_ok=True)
    (content_dir / "app.py").write_text(full_content)

    store.save_index(
        owner="local",
        name="testapp",
        source_files=["app.py"],
        symbols=symbols,
        raw_files={"app.py": full_content},
        languages={"python": 1},
    )
    return store, symbols


# ---------------------------------------------------------------------------
# get_symbol
# ---------------------------------------------------------------------------


class TestGetSymbolHappyPath:
    """Happy-path tests for get_symbol."""

    def test_returns_source_for_known_symbol(self, tmp_path):
        """Should return source code for a valid symbol ID."""
        _make_indexed_repo(tmp_path)
        result = get_symbol(
            repo="local/testapp",
            symbol_id="app.py::greet#function",
            storage_path=str(tmp_path),
        )

        assert "error" not in result
        assert "source" in result
        assert "greet" in result["source"]
        assert result["kind"] == "function"

    def test_returns_correct_metadata_fields(self, tmp_path):
        """Result should include id, kind, name, file, line, end_line, _meta."""
        _make_indexed_repo(tmp_path)
        result = get_symbol(
            repo="local/testapp",
            symbol_id="app.py::greet#function",
            storage_path=str(tmp_path),
        )

        assert "id" in result
        assert "name" in result
        assert "file" in result
        assert result["line"] == 1
        assert result["end_line"] == 2
        assert "_meta" in result
        assert "timing_ms" in result["_meta"]

    def test_verify_content_hash(self, tmp_path):
        """verify=True should check content hash and report match."""
        _make_indexed_repo(tmp_path)
        result = get_symbol(
            repo="local/testapp",
            symbol_id="app.py::greet#function",
            verify=True,
            storage_path=str(tmp_path),
        )

        assert "error" not in result
        assert result["_meta"]["content_verified"] is True

    def test_context_lines(self, tmp_path):
        """context_lines > 0 should include surrounding code."""
        _make_indexed_repo(tmp_path)
        result = get_symbol(
            repo="local/testapp",
            symbol_id="app.py::helper#function",
            context_lines=5,
            storage_path=str(tmp_path),
        )

        assert "error" not in result
        # helper is the second function, so there should be context_before
        assert "context_before" in result


class TestGetSymbolErrors:
    """Error-handling tests for get_symbol."""

    def test_missing_symbol_returns_error(self, tmp_path):
        """An unknown symbol ID should return an error dict."""
        _make_indexed_repo(tmp_path)
        result = get_symbol(
            repo="local/testapp",
            symbol_id="app.py::nonexistent#function",
            storage_path=str(tmp_path),
        )

        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_missing_repo_returns_error(self, tmp_path):
        """An unknown repo should return an error dict."""
        result = get_symbol(
            repo="nobody/norepo",
            symbol_id="any::sym#function",
            storage_path=str(tmp_path),
        )

        assert "error" in result


class TestGetSymbolEdgeCases:
    """Edge-case tests for get_symbol."""

    def test_zero_context_lines_no_context_fields(self, tmp_path):
        """context_lines=0 should not add context_before/context_after."""
        _make_indexed_repo(tmp_path)
        result = get_symbol(
            repo="local/testapp",
            symbol_id="app.py::greet#function",
            context_lines=0,
            storage_path=str(tmp_path),
        )

        assert "error" not in result
        assert "context_before" not in result
        assert "context_after" not in result

    def test_source_is_wrapped(self, tmp_path):
        """Source code should be wrapped with untrusted content markers."""
        _make_indexed_repo(tmp_path)
        result = get_symbol(
            repo="local/testapp",
            symbol_id="app.py::greet#function",
            storage_path=str(tmp_path),
        )

        assert result["source"].startswith("<<<UNTRUSTED_CODE_")


# ---------------------------------------------------------------------------
# get_symbols (batch)
# ---------------------------------------------------------------------------


class TestGetSymbolsHappyPath:
    """Happy-path tests for get_symbols."""

    def test_returns_multiple_symbols(self, tmp_path):
        """Should return source for multiple valid symbol IDs."""
        _make_indexed_repo(tmp_path)
        result = get_symbols(
            repo="local/testapp",
            symbol_ids=[
                "app.py::greet#function",
                "app.py::helper#function",
            ],
            storage_path=str(tmp_path),
        )

        assert "error" not in result
        assert len(result["symbols"]) == 2
        assert result["errors"] == []
        assert result["_meta"]["symbol_count"] == 2

    def test_single_symbol(self, tmp_path):
        """Should work with a single-element list."""
        _make_indexed_repo(tmp_path)
        result = get_symbols(
            repo="local/testapp",
            symbol_ids=["app.py::greet#function"],
            storage_path=str(tmp_path),
        )

        assert len(result["symbols"]) == 1
        assert "greet" in result["symbols"][0]["name"]


class TestGetSymbolsErrors:
    """Error-handling tests for get_symbols."""

    def test_missing_symbol_in_batch(self, tmp_path):
        """A missing symbol should appear in errors, not crash the batch."""
        _make_indexed_repo(tmp_path)
        result = get_symbols(
            repo="local/testapp",
            symbol_ids=[
                "app.py::greet#function",
                "app.py::nonexistent#function",
            ],
            storage_path=str(tmp_path),
        )

        assert len(result["symbols"]) == 1
        assert len(result["errors"]) == 1
        assert "nonexistent" in result["errors"][0]["error"]

    def test_all_missing_symbols(self, tmp_path):
        """If all symbols are missing, symbols list should be empty."""
        _make_indexed_repo(tmp_path)
        result = get_symbols(
            repo="local/testapp",
            symbol_ids=["app.py::x#function", "app.py::y#function"],
            storage_path=str(tmp_path),
        )

        assert result["symbols"] == []
        assert len(result["errors"]) == 2

    def test_missing_repo_returns_error(self, tmp_path):
        """An unknown repo should return a top-level error."""
        result = get_symbols(
            repo="nobody/norepo",
            symbol_ids=["any::sym#function"],
            storage_path=str(tmp_path),
        )

        assert "error" in result
