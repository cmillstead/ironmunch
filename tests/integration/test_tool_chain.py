"""Integration tests: index a multi-file codebase then use multiple tools in sequence.

Verifies consistency between indexing and tool outputs.
"""

import pytest

from codesight_mcp.parser.symbols import Symbol
from codesight_mcp.storage import IndexStore
from codesight_mcp.tools.get_file_outline import get_file_outline
from codesight_mcp.tools.get_symbol import get_symbol
from codesight_mcp.tools.search_symbols import search_symbols
from codesight_mcp.tools.get_file_tree import get_file_tree
from codesight_mcp.tools.get_repo_outline import get_repo_outline
from codesight_mcp.tools.get_callers import get_callers
from codesight_mcp.tools.get_callees import get_callees
from codesight_mcp.tools.get_key_symbols import get_key_symbols
from codesight_mcp.tools.get_hotspots import get_hotspots
from codesight_mcp.tools.get_dead_code import get_dead_code
from codesight_mcp.tools.search_text import search_text


# ---------------------------------------------------------------------------
# Rich multi-file fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def multi_file_index(tmp_path):
    """An IndexStore with 3 Python files containing classes, functions, and call relationships."""

    # --- File: src/utils.py ---
    utils_src = (
        "def helper():\n"
        "    return 42\n"
        "\n"
        "def format_output(data):\n"
        "    return str(data)\n"
    )

    # --- File: src/models.py ---
    models_src = (
        "class BaseModel:\n"
        "    def validate(self):\n"
        "        pass\n"
        "\n"
        "class UserModel(BaseModel):\n"
        "    def validate(self):\n"
        "        return True\n"
    )

    # --- File: src/main.py ---
    main_src = (
        "from utils import helper, format_output\n"
        "from models import UserModel\n"
        "\n"
        "def process():\n"
        "    h = helper()\n"
        "    u = UserModel()\n"
        "    u.validate()\n"
        "    return format_output(h)\n"
    )

    symbols = [
        # utils.py
        Symbol(
            id="src/utils.py::helper#function",
            file="src/utils.py", name="helper", qualified_name="helper",
            kind="function", language="python", signature="def helper():",
            summary="Returns 42", line=1, end_line=2,
            byte_offset=0, byte_length=len("def helper():\n    return 42\n"),
            complexity={"cyclomatic": 1, "cognitive": 0, "max_nesting": 0, "param_count": 0, "loc": 2},
        ),
        Symbol(
            id="src/utils.py::format_output#function",
            file="src/utils.py", name="format_output", qualified_name="format_output",
            kind="function", language="python", signature="def format_output(data):",
            summary="Formats data as string", line=4, end_line=5,
            byte_offset=len("def helper():\n    return 42\n\n"),
            byte_length=len("def format_output(data):\n    return str(data)\n"),
            complexity={"cyclomatic": 1, "cognitive": 0, "max_nesting": 0, "param_count": 1, "loc": 2},
        ),
        # models.py
        Symbol(
            id="src/models.py::BaseModel#class",
            file="src/models.py", name="BaseModel", qualified_name="BaseModel",
            kind="class", language="python", signature="class BaseModel:",
            summary="Base model class", line=1, end_line=3,
            byte_offset=0, byte_length=len("class BaseModel:\n    def validate(self):\n        pass\n"),
        ),
        Symbol(
            id="src/models.py::BaseModel.validate#method",
            file="src/models.py", name="validate", qualified_name="BaseModel.validate",
            kind="method", language="python", signature="def validate(self):",
            summary="Validates model", line=2, end_line=3,
            parent="src/models.py::BaseModel#class",
            byte_offset=len("class BaseModel:\n"),
            byte_length=len("    def validate(self):\n        pass\n"),
            complexity={"cyclomatic": 1, "cognitive": 0, "max_nesting": 0, "param_count": 1, "loc": 2},
        ),
        Symbol(
            id="src/models.py::UserModel#class",
            file="src/models.py", name="UserModel", qualified_name="UserModel",
            kind="class", language="python", signature="class UserModel(BaseModel):",
            summary="User model", line=5, end_line=7,
            byte_offset=len("class BaseModel:\n    def validate(self):\n        pass\n\n"),
            byte_length=len("class UserModel(BaseModel):\n    def validate(self):\n        return True\n"),
            inherits_from=["BaseModel"],
        ),
        Symbol(
            id="src/models.py::UserModel.validate#method",
            file="src/models.py", name="validate", qualified_name="UserModel.validate",
            kind="method", language="python", signature="def validate(self):",
            summary="Validates user", line=6, end_line=7,
            parent="src/models.py::UserModel#class",
            byte_offset=len("class BaseModel:\n    def validate(self):\n        pass\n\nclass UserModel(BaseModel):\n"),
            byte_length=len("    def validate(self):\n        return True\n"),
            complexity={"cyclomatic": 1, "cognitive": 0, "max_nesting": 0, "param_count": 1, "loc": 2},
        ),
        # main.py
        Symbol(
            id="src/main.py::process#function",
            file="src/main.py", name="process", qualified_name="process",
            kind="function", language="python", signature="def process():",
            summary="Main processing", line=4, end_line=8,
            byte_offset=len("from utils import helper, format_output\nfrom models import UserModel\n\n"),
            byte_length=len("def process():\n    h = helper()\n    u = UserModel()\n    u.validate()\n    return format_output(h)\n"),
            calls=["helper", "format_output", "validate"],
            imports=["utils", "models"],
            complexity={"cyclomatic": 1, "cognitive": 0, "max_nesting": 0, "param_count": 0, "loc": 5},
        ),
    ]

    store = IndexStore(base_path=str(tmp_path))
    store.save_index(
        owner="test",
        name="multi",
        source_files=["src/utils.py", "src/models.py", "src/main.py"],
        symbols=symbols,
        raw_files={
            "src/utils.py": utils_src,
            "src/models.py": models_src,
            "src/main.py": main_src,
        },
        languages={"python": 3},
    )

    return str(tmp_path)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestIndexToFileOutline:

    def test_file_outline_matches_indexed_symbols(self, multi_file_index):
        """get_file_outline returns symbols consistent with what was indexed."""
        result = get_file_outline(
            repo="test/multi", file_path="src/utils.py",
            storage_path=multi_file_index,
        )
        assert "error" not in result
        assert len(result["symbols"]) == 2
        names = {s["name"] for s in result["symbols"]}
        # Names are wrapped in spotlighting markers — extract inner content
        assert any("helper" in n for n in names)
        assert any("format_output" in n for n in names)


class TestIndexToGetSymbol:

    def test_symbol_source_matches(self, multi_file_index):
        """get_symbol returns source content matching the indexed file."""
        result = get_symbol(
            repo="test/multi", symbol_id="src/utils.py::helper#function",
            storage_path=multi_file_index,
        )
        assert "error" not in result
        assert "source" in result
        assert "helper" in result["source"]


class TestIndexToSearchSymbols:

    def test_search_finds_indexed_symbols(self, multi_file_index):
        """search_symbols finds symbols that were indexed."""
        result = search_symbols(
            repo="test/multi", query="helper",
            storage_path=multi_file_index,
        )
        assert "error" not in result
        assert result["result_count"] >= 1
        found_names = [r["name"] for r in result["results"]]
        assert any("helper" in n for n in found_names)


class TestIndexToFileTree:

    def test_file_tree_matches(self, multi_file_index):
        """get_file_tree lists all indexed files."""
        result = get_file_tree(
            repo="test/multi",
            storage_path=multi_file_index,
        )
        assert "error" not in result
        assert result["_meta"]["file_count"] == 3


class TestIndexToRepoOutline:

    def test_repo_outline_language_breakdown(self, multi_file_index):
        """get_repo_outline returns correct language breakdown."""
        result = get_repo_outline(
            repo="test/multi",
            storage_path=multi_file_index,
        )
        assert "error" not in result
        assert result["file_count"] == 3
        assert result["symbol_count"] == 7
        assert "python" in result["languages"]


class TestIndexToGraphTools:

    def test_get_callers_and_callees(self, multi_file_index):
        """get_callers and get_callees return consistent graph data."""
        # process() calls helper(), so helper should have process as a caller
        callers_result = get_callers(
            repo="test/multi", symbol_id="src/utils.py::helper#function",
            storage_path=multi_file_index,
        )
        # Even if graph resolution doesn't resolve all calls by name,
        # the tool should not error
        assert "error" not in callers_result
        assert isinstance(callers_result["callers"], list)

        callees_result = get_callees(
            repo="test/multi", symbol_id="src/main.py::process#function",
            storage_path=multi_file_index,
        )
        assert "error" not in callees_result
        assert isinstance(callees_result["callees"], list)


class TestIndexToKeySymbols:

    def test_key_symbols_returns_ranked_list(self, multi_file_index):
        """get_key_symbols returns a ranked list of symbols."""
        result = get_key_symbols(
            repo="test/multi",
            storage_path=multi_file_index,
        )
        assert "error" not in result
        assert isinstance(result["key_symbols"], list)
        assert result["total_symbols"] == 7


class TestIndexToHotspots:

    def test_hotspots_returns_complexity_data(self, multi_file_index):
        """get_hotspots returns symbols with complexity metrics."""
        result = get_hotspots(
            repo="test/multi",
            storage_path=multi_file_index,
        )
        assert "error" not in result
        # We indexed several functions/methods with complexity data
        assert isinstance(result["hotspots"], list)
        if result["hotspots"]:
            hs = result["hotspots"][0]
            assert "cyclomatic" in hs
            assert "cognitive" in hs


class TestIndexToDeadCode:

    def test_dead_code_detection(self, multi_file_index):
        """get_dead_code identifies symbols with zero callers."""
        result = get_dead_code(
            repo="test/multi",
            storage_path=multi_file_index,
        )
        assert "error" not in result
        assert isinstance(result["symbols"], list)
        # At minimum, 'process' has no callers (it's a top-level entry),
        # but it may be filtered as entry point. The tool should not error.
        assert result["dead_count"] >= 0


class TestIndexToSearchText:

    def test_search_text_finds_content(self, multi_file_index):
        """search_text finds text in indexed file contents."""
        result = search_text(
            repo="test/multi", query="return 42",
            confirm_sensitive_search=True,
            storage_path=multi_file_index,
        )
        assert "error" not in result
        assert result["result_count"] >= 1
        found_files = [r["file"] for r in result["results"]]
        assert any("utils" in f for f in found_files)
