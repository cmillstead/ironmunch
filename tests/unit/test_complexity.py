"""Unit tests for AST complexity extraction."""

import pytest
from codesight_mcp.parser.complexity import compute_complexity, _BRANCH_NODES


class TestComputeComplexity:
    """Test compute_complexity with real tree-sitter AST nodes."""

    def _parse(self, code: str, language: str = "python"):
        """Parse code and return the first function/method node."""
        from codesight_mcp.parser.extractor import _get_parser
        parser = _get_parser(language)
        tree = parser.parse(code.encode())
        # Walk to find first function node
        return self._find_function(tree.root_node, language)

    def _find_function(self, node, language):
        """Recursively find the first function-like node."""
        func_types = {
            "python": {"function_definition"},
            "javascript": {"function_declaration", "arrow_function", "method_definition"},
            "typescript": {"function_declaration", "arrow_function", "method_definition"},
            "go": {"function_declaration", "method_declaration"},
            "rust": {"function_item"},
            "java": {"method_declaration"},
        }
        targets = func_types.get(language, {"function_definition"})
        if node.type in targets:
            return node
        for child in node.children:
            result = self._find_function(child, language)
            if result:
                return result
        return None

    def test_simple_function(self):
        """A function with no branches has cyclomatic=1, cognitive=0."""
        node = self._parse("def f():\n    return 1\n")
        result = compute_complexity(node, "python")
        assert result["cyclomatic"] == 1
        assert result["cognitive"] == 0
        assert result["max_nesting"] == 0

    def test_single_if(self):
        """One if adds cyclomatic=2, cognitive=1."""
        code = "def f(x):\n    if x:\n        return 1\n    return 0\n"
        node = self._parse(code)
        result = compute_complexity(node, "python")
        assert result["cyclomatic"] == 2
        assert result["cognitive"] == 1

    def test_nested_if(self):
        """Nested if: cyclomatic=3, cognitive=1+(1+1 nesting)=3."""
        code = "def f(x, y):\n    if x:\n        if y:\n            return 1\n    return 0\n"
        node = self._parse(code)
        result = compute_complexity(node, "python")
        assert result["cyclomatic"] == 3
        assert result["cognitive"] == 3
        assert result["max_nesting"] == 2

    def test_for_loop(self):
        """For loop counts as a branch."""
        code = "def f(items):\n    for x in items:\n        print(x)\n"
        node = self._parse(code)
        result = compute_complexity(node, "python")
        assert result["cyclomatic"] == 2
        assert result["cognitive"] == 1

    def test_try_except(self):
        """Try/except: except clause is a branch."""
        code = "def f():\n    try:\n        do()\n    except Exception:\n        pass\n"
        node = self._parse(code)
        result = compute_complexity(node, "python")
        assert result["cyclomatic"] == 2
        # except_clause is nested inside try_statement (nesting depth 1)
        assert result["cognitive"] == 2

    def test_elif_chain(self):
        """if/elif/elif: each is a separate branch."""
        code = (
            "def f(x):\n"
            "    if x == 1:\n"
            "        return 'a'\n"
            "    elif x == 2:\n"
            "        return 'b'\n"
            "    elif x == 3:\n"
            "        return 'c'\n"
            "    return 'd'\n"
        )
        node = self._parse(code)
        result = compute_complexity(node, "python")
        assert result["cyclomatic"] == 4  # 1 + if + elif + elif

    def test_while_loop(self):
        """While loop is a branch point."""
        code = "def f():\n    while True:\n        break\n"
        node = self._parse(code)
        result = compute_complexity(node, "python")
        assert result["cyclomatic"] == 2

    def test_param_count(self):
        """Parameter count extraction."""
        code = "def f(a, b, c=1):\n    pass\n"
        node = self._parse(code)
        result = compute_complexity(node, "python")
        assert result["param_count"] == 3

    def test_no_params(self):
        """Zero-param function."""
        code = "def f():\n    pass\n"
        node = self._parse(code)
        result = compute_complexity(node, "python")
        assert result["param_count"] == 0

    def test_loc(self):
        """Lines of code calculation."""
        code = "def f():\n    x = 1\n    y = 2\n    return x + y\n"
        node = self._parse(code)
        result = compute_complexity(node, "python")
        assert result["loc"] == 4

    def test_returns_dict_keys(self):
        """Result always has all expected keys."""
        code = "def f():\n    pass\n"
        node = self._parse(code)
        result = compute_complexity(node, "python")
        assert set(result.keys()) == {"cyclomatic", "cognitive", "max_nesting", "param_count", "loc"}

    def test_none_node(self):
        """None node returns zeros."""
        result = compute_complexity(None, "python")
        assert result["cyclomatic"] == 1
        assert result["cognitive"] == 0


class TestComplexityJavaScript:
    """Verify branch detection works for JavaScript."""

    def _parse(self, code: str):
        from codesight_mcp.parser.extractor import _get_parser
        parser = _get_parser("javascript")
        tree = parser.parse(code.encode())
        return self._find_function(tree.root_node)

    def _find_function(self, node):
        if node.type in {"function_declaration", "arrow_function", "method_definition"}:
            return node
        for child in node.children:
            result = self._find_function(child)
            if result:
                return result
        return None

    def test_js_if_else(self):
        code = "function f(x) { if (x) { return 1; } else { return 0; } }\n"
        node = self._parse(code)
        result = compute_complexity(node, "javascript")
        assert result["cyclomatic"] >= 2

    def test_js_ternary(self):
        code = "function f(x) { return x ? 1 : 0; }\n"
        node = self._parse(code)
        result = compute_complexity(node, "javascript")
        assert result["cyclomatic"] == 2

    def test_js_switch(self):
        code = (
            "function f(x) {\n"
            "  switch(x) {\n"
            "    case 1: return 'a';\n"
            "    case 2: return 'b';\n"
            "    default: return 'c';\n"
            "  }\n"
            "}\n"
        )
        node = self._parse(code)
        result = compute_complexity(node, "javascript")
        assert result["cyclomatic"] >= 3  # switch_case nodes


class TestComplexityGo:
    """Verify Go-specific branch nodes."""

    def _parse(self, code: str):
        from codesight_mcp.parser.extractor import _get_parser
        parser = _get_parser("go")
        tree = parser.parse(code.encode())
        return self._find_function(tree.root_node)

    def _find_function(self, node):
        if node.type in {"function_declaration", "method_declaration"}:
            return node
        for child in node.children:
            result = self._find_function(child)
            if result:
                return result
        return None

    def test_go_if(self):
        code = "package main\nfunc f(x int) int { if x > 0 { return 1 }; return 0 }\n"
        node = self._parse(code)
        result = compute_complexity(node, "go")
        assert result["cyclomatic"] == 2


class TestComplexityRust:
    """Verify Rust-specific branch nodes."""

    def _parse(self, code: str):
        from codesight_mcp.parser.extractor import _get_parser
        parser = _get_parser("rust")
        tree = parser.parse(code.encode())
        return self._find_function(tree.root_node)

    def _find_function(self, node):
        if node.type == "function_item":
            return node
        for child in node.children:
            result = self._find_function(child)
            if result:
                return result
        return None

    def test_rust_match(self):
        code = "fn f(x: i32) -> i32 { match x { 1 => 10, 2 => 20, _ => 0 } }\n"
        node = self._parse(code)
        result = compute_complexity(node, "rust")
        assert result["cyclomatic"] >= 3  # match arms


class TestBranchNodes:
    """Test the branch node set itself."""

    def test_common_nodes_present(self):
        assert "if_statement" in _BRANCH_NODES
        assert "for_statement" in _BRANCH_NODES
        assert "while_statement" in _BRANCH_NODES
