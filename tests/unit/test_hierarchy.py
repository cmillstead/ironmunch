"""Tests for parser/hierarchy.py: build_symbol_tree and flatten_tree."""

import pytest

from codesight_mcp.parser.symbols import Symbol
from codesight_mcp.parser.hierarchy import SymbolNode, build_symbol_tree, flatten_tree


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sym(name, kind="function", parent=None):
    """Create a minimal Symbol for hierarchy tests."""
    sid = f"test.py::{name}"
    return Symbol(
        id=sid,
        file="test.py",
        name=name,
        qualified_name=name,
        kind=kind,
        language="python",
        signature=f"def {name}():" if kind != "class" else f"class {name}:",
        parent=f"test.py::{parent}" if parent else None,
        byte_offset=0,
        byte_length=10,
    )


# ---------------------------------------------------------------------------
# build_symbol_tree
# ---------------------------------------------------------------------------


class TestBuildSymbolTree:
    """Tests for build_symbol_tree()."""

    def test_empty_list(self):
        """Empty symbol list returns empty tree."""
        assert build_symbol_tree([]) == []

    def test_single_symbol(self):
        """Single symbol yields one root node."""
        symbols = [_sym("foo")]
        tree = build_symbol_tree(symbols)
        assert len(tree) == 1
        assert tree[0].symbol.name == "foo"
        assert tree[0].children == []

    def test_class_with_methods(self):
        """Methods become children of their parent class."""
        cls = _sym("MyClass", kind="class")
        method_a = _sym("method_a", kind="method", parent="MyClass")
        method_b = _sym("method_b", kind="method", parent="MyClass")
        tree = build_symbol_tree([cls, method_a, method_b])

        assert len(tree) == 1  # one root (the class)
        assert tree[0].symbol.name == "MyClass"
        assert len(tree[0].children) == 2
        child_names = {c.symbol.name for c in tree[0].children}
        assert child_names == {"method_a", "method_b"}

    def test_multiple_top_level(self):
        """Multiple top-level symbols all appear as roots."""
        symbols = [_sym("foo"), _sym("bar"), _sym("baz")]
        tree = build_symbol_tree(symbols)
        assert len(tree) == 3
        names = {n.symbol.name for n in tree}
        assert names == {"foo", "bar", "baz"}

    def test_deeply_nested(self):
        """Three-level nesting: module > class > method."""
        outer = _sym("Outer", kind="class")
        inner = _sym("Inner", kind="class", parent="Outer")
        method = _sym("do_thing", kind="method", parent="Inner")
        tree = build_symbol_tree([outer, inner, method])

        assert len(tree) == 1
        assert tree[0].symbol.name == "Outer"
        assert len(tree[0].children) == 1
        inner_node = tree[0].children[0]
        assert inner_node.symbol.name == "Inner"
        assert len(inner_node.children) == 1
        assert inner_node.children[0].symbol.name == "do_thing"


# ---------------------------------------------------------------------------
# flatten_tree
# ---------------------------------------------------------------------------


class TestFlattenTree:
    """Tests for flatten_tree()."""

    def test_empty_tree(self):
        """Empty tree returns empty list."""
        assert flatten_tree([]) == []

    def test_single_node_depth_zero(self):
        """Single node at default depth=0."""
        tree = [SymbolNode(symbol=_sym("foo"))]
        result = flatten_tree(tree)
        assert len(result) == 1
        sym, depth = result[0]
        assert sym.name == "foo"
        assert depth == 0

    def test_depth_increments(self):
        """Children are one depth level deeper than parents."""
        child = SymbolNode(symbol=_sym("method_a"))
        parent = SymbolNode(symbol=_sym("MyClass", kind="class"), children=[child])
        result = flatten_tree([parent])

        assert len(result) == 2
        assert result[0][0].name == "MyClass"
        assert result[0][1] == 0
        assert result[1][0].name == "method_a"
        assert result[1][1] == 1
