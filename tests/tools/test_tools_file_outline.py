"""Tests for get_file_outline tool."""

import pytest

from codesight_mcp.tools.get_file_outline import get_file_outline
from codesight_mcp.core.validation import ValidationError
from codesight_mcp.parser import Symbol


def _index_with_class(tmp_path):
    """Create an index with a class containing a method."""
    from codesight_mcp.storage import IndexStore

    src = (
        "class Calculator:\n"
        "    def add(self, a, b):\n"
        "        return a + b\n"
    )
    class_sym = Symbol(
        id="calc.py::Calculator#class",
        file="calc.py",
        name="Calculator",
        qualified_name="Calculator",
        kind="class",
        language="python",
        signature="class Calculator:",
        summary="A calculator",
        line=1, end_line=3,
        byte_offset=0, byte_length=len(src),
    )
    method_sym = Symbol(
        id="calc.py::Calculator.add#method",
        file="calc.py",
        name="add",
        qualified_name="Calculator.add",
        kind="method",
        language="python",
        signature="def add(self, a, b):",
        summary="Add two numbers",
        parent="calc.py::Calculator#class",
        line=2, end_line=3,
        byte_offset=21, byte_length=35,
    )

    store = IndexStore(base_path=str(tmp_path))
    store.save_index(
        owner="local",
        name="myproject",
        source_files=["calc.py", "empty.py"],
        symbols=[class_sym, method_sym],
        raw_files={"calc.py": src, "empty.py": "# empty\n"},
        languages={"python": 2},
    )
    return store


class TestGetFileOutlineHappyPath:
    """Happy-path tests for get_file_outline."""

    def test_returns_symbols_for_known_file(self, tmp_path):
        """A file with symbols should return them in the outline."""
        _index_with_class(tmp_path)
        result = get_file_outline(
            repo="local/myproject",
            file_path="calc.py",
            storage_path=str(tmp_path),
        )

        assert "error" not in result
        assert result["language"] == "python"
        symbols = result["symbols"]
        assert len(symbols) >= 1
        # Top-level should be the class
        class_node = symbols[0]
        assert class_node["kind"] == "class"
        assert "Calculator" in class_node["name"]

    def test_class_has_method_children(self, tmp_path):
        """Methods should appear as children of their parent class."""
        _index_with_class(tmp_path)
        result = get_file_outline(
            repo="local/myproject",
            file_path="calc.py",
            storage_path=str(tmp_path),
        )

        class_node = result["symbols"][0]
        assert "children" in class_node
        assert len(class_node["children"]) == 1
        assert class_node["children"][0]["kind"] == "method"

    def test_empty_file_returns_empty_symbols(self, tmp_path):
        """A file with no symbols should return an empty symbols list."""
        _index_with_class(tmp_path)
        result = get_file_outline(
            repo="local/myproject",
            file_path="empty.py",
            storage_path=str(tmp_path),
        )

        assert "error" not in result
        assert result["symbols"] == []

    def test_meta_envelope_present(self, tmp_path):
        """Result should include _meta with timing and symbol count."""
        _index_with_class(tmp_path)
        result = get_file_outline(
            repo="local/myproject",
            file_path="calc.py",
            storage_path=str(tmp_path),
        )

        assert "_meta" in result
        assert "timing_ms" in result["_meta"]
        assert result["_meta"]["symbol_count"] >= 1


class TestGetFileOutlineErrors:
    """Error-handling tests for get_file_outline."""

    def test_unknown_file_returns_error_dict(self, tmp_path):
        """A file not in the index should return an error dict."""
        _index_with_class(tmp_path)
        result = get_file_outline(
            repo="local/myproject",
            file_path="nonexistent.py",
            storage_path=str(tmp_path),
        )
        assert "error" in result
        assert "File not found in index" in result["error"]

    def test_unknown_repo_returns_error(self, tmp_path):
        """A repo that does not exist should return an error dict."""
        result = get_file_outline(
            repo="nobody/norepo",
            file_path="any.py",
            storage_path=str(tmp_path),
        )
        assert "error" in result

    def test_repo_not_indexed_returns_error(self, tmp_path):
        """A valid-looking repo with no index on disk should return an error."""
        result = get_file_outline(
            repo="owner/missing",
            file_path="foo.py",
            storage_path=str(tmp_path),
        )
        assert "error" in result


class TestGetFileOutlineEdgeCases:
    """Edge-case tests for get_file_outline."""

    def test_symbol_line_numbers_present(self, tmp_path):
        """Each symbol in the outline should have a line number."""
        _index_with_class(tmp_path)
        result = get_file_outline(
            repo="local/myproject",
            file_path="calc.py",
            storage_path=str(tmp_path),
        )

        for sym in result["symbols"]:
            assert "line" in sym
            assert sym["line"] >= 1

    def test_result_contains_repo_field(self, tmp_path):
        """The result should echo back the repo identifier."""
        _index_with_class(tmp_path)
        result = get_file_outline(
            repo="local/myproject",
            file_path="calc.py",
            storage_path=str(tmp_path),
        )

        assert result["repo"] == "local/myproject"

    def test_file_field_is_wrapped(self, tmp_path):
        """The file field should be wrapped with untrusted content markers."""
        _index_with_class(tmp_path)
        result = get_file_outline(
            repo="local/myproject",
            file_path="calc.py",
            storage_path=str(tmp_path),
        )

        assert result["file"].startswith("<<<UNTRUSTED_CODE_")
