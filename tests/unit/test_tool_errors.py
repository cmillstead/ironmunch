"""Tests for consistent error handling across tool handlers.

Verifies that all tools return dicts with an 'error' key (or raise
ValidationError) for common failure modes: repo not found, symbol not found,
invalid parameters.
"""

import pytest

from codesight_mcp.core.validation import ValidationError
from codesight_mcp.parser.symbols import Symbol
from codesight_mcp.storage import IndexStore
from codesight_mcp.tools.get_symbol import get_symbol
from codesight_mcp.tools.get_file_outline import get_file_outline
from codesight_mcp.tools.search_symbols import search_symbols
from codesight_mcp.tools.get_callers import get_callers
from codesight_mcp.tools.get_callees import get_callees
from codesight_mcp.tools.get_imports import get_imports
from codesight_mcp.tools.get_impact import get_impact
from codesight_mcp.tools.get_type_hierarchy import get_type_hierarchy
from codesight_mcp.tools.get_hotspots import get_hotspots
from codesight_mcp.tools.get_dead_code import get_dead_code


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def indexed_store(tmp_path):
    """An IndexStore with one function symbol indexed."""
    src = "def greet():\n    return 'hi'\n"
    symbols = [
        Symbol(
            id="greet-py::greet",
            file="greet.py",
            name="greet",
            qualified_name="greet",
            kind="function",
            language="python",
            signature="def greet():",
            summary="Greets",
            byte_offset=0,
            byte_length=len(src),
        )
    ]
    store = IndexStore(base_path=str(tmp_path))
    store.save_index(
        owner="test",
        name="errors",
        source_files=["greet.py"],
        symbols=symbols,
        raw_files={"greet.py": src},
        languages={"python": 1},
    )
    return str(tmp_path)


def _assert_error(result):
    """Assert result is a dict with an 'error' key."""
    assert isinstance(result, dict), f"Expected dict, got {type(result)}"
    assert "error" in result, f"Expected 'error' key in {result}"
    assert isinstance(result["error"], str)


# ---------------------------------------------------------------------------
# get_symbol errors
# ---------------------------------------------------------------------------


class TestGetSymbolErrors:

    def test_repo_not_found(self, tmp_path):
        result = get_symbol(repo="ghost/repo", symbol_id="x", storage_path=str(tmp_path))
        _assert_error(result)

    def test_symbol_not_found(self, indexed_store):
        result = get_symbol(repo="test/errors", symbol_id="nonexistent::sym", storage_path=indexed_store)
        _assert_error(result)
        assert "not found" in result["error"].lower()

    def test_no_symbol_id_or_file_line(self, indexed_store):
        result = get_symbol(repo="test/errors", storage_path=indexed_store)
        _assert_error(result)


# ---------------------------------------------------------------------------
# get_file_outline errors
# ---------------------------------------------------------------------------


class TestGetFileOutlineErrors:

    def test_repo_not_found(self, tmp_path):
        result = get_file_outline(repo="ghost/repo", file_path="x.py", storage_path=str(tmp_path))
        _assert_error(result)

    def test_file_not_found(self, indexed_store):
        result = get_file_outline(repo="test/errors", file_path="missing.py", storage_path=indexed_store)
        _assert_error(result)


# ---------------------------------------------------------------------------
# search_symbols errors
# ---------------------------------------------------------------------------


class TestSearchSymbolsErrors:

    def test_repo_not_found(self, tmp_path):
        result = search_symbols(repo="ghost/repo", query="foo", storage_path=str(tmp_path))
        _assert_error(result)

    def test_no_repo_specified(self, tmp_path):
        result = search_symbols(query="foo", storage_path=str(tmp_path))
        _assert_error(result)


# ---------------------------------------------------------------------------
# get_callers errors
# ---------------------------------------------------------------------------


class TestGetCallersErrors:

    def test_repo_not_found(self, tmp_path):
        result = get_callers(repo="ghost/repo", symbol_id="x", storage_path=str(tmp_path))
        _assert_error(result)

    def test_symbol_not_found(self, indexed_store):
        result = get_callers(repo="test/errors", symbol_id="nonexistent::sym", storage_path=indexed_store)
        _assert_error(result)


# ---------------------------------------------------------------------------
# get_imports errors
# ---------------------------------------------------------------------------


class TestGetImportsErrors:

    def test_repo_not_found(self, tmp_path):
        result = get_imports(repo="ghost/repo", file="x.py", storage_path=str(tmp_path))
        _assert_error(result)

    def test_invalid_direction(self, indexed_store):
        result = get_imports(repo="test/errors", file="greet.py", direction="sideways", storage_path=indexed_store)
        _assert_error(result)
        assert "invalid direction" in result["error"].lower()


# ---------------------------------------------------------------------------
# get_impact errors
# ---------------------------------------------------------------------------


class TestGetImpactErrors:

    def test_repo_not_found(self, tmp_path):
        result = get_impact(repo="ghost/repo", symbol_id="x", storage_path=str(tmp_path))
        _assert_error(result)

    def test_symbol_not_found(self, indexed_store):
        result = get_impact(repo="test/errors", symbol_id="nonexistent::sym", storage_path=indexed_store)
        _assert_error(result)


# ---------------------------------------------------------------------------
# get_type_hierarchy errors
# ---------------------------------------------------------------------------


class TestGetTypeHierarchyErrors:

    def test_repo_not_found(self, tmp_path):
        result = get_type_hierarchy(repo="ghost/repo", symbol_id="x", storage_path=str(tmp_path))
        _assert_error(result)

    def test_symbol_not_found(self, indexed_store):
        result = get_type_hierarchy(repo="test/errors", symbol_id="nonexistent::sym", storage_path=indexed_store)
        _assert_error(result)


# ---------------------------------------------------------------------------
# get_hotspots errors
# ---------------------------------------------------------------------------


class TestGetHotspotsErrors:

    def test_repo_not_found(self, tmp_path):
        result = get_hotspots(repo="ghost/repo", storage_path=str(tmp_path))
        _assert_error(result)


# ---------------------------------------------------------------------------
# get_dead_code errors
# ---------------------------------------------------------------------------


class TestGetDeadCodeErrors:

    def test_repo_not_found(self, tmp_path):
        result = get_dead_code(repo="ghost/repo", storage_path=str(tmp_path))
        _assert_error(result)
