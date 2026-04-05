"""Tests for language depth batch 3: GLSL/HLSL call extraction + complexity extras.

Verifies call extraction for GLSL and HLSL shader languages, and complexity
branch/nesting extras for Erlang, Scala, Haskell, and Lua.
"""

from codesight_mcp.parser.complexity import compute_complexity
from codesight_mcp.parser.extractor import _get_parser, parse_file


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _symbol_names(symbols):
    """Extract symbol names as a set for assertion convenience."""
    return {s.name for s in symbols}


def _find_symbol(symbols, name):
    """Find a symbol by name."""
    for s in symbols:
        if s.name == name:
            return s
    return None


def _find_function_node(source: str, language: str, func_node_type: str):
    """Parse source and find the first function node of the given type."""
    parser = _get_parser(language)
    assert parser is not None, f"No parser available for {language}"
    tree = parser.parse(source.encode("utf-8"))
    root = tree.root_node

    # BFS to find the function node
    stack = [root]
    while stack:
        node = stack.pop(0)
        if node.type == func_node_type:
            return node
        stack.extend(node.children)
    return None


# ---------------------------------------------------------------------------
# Call extraction tests — GLSL
# ---------------------------------------------------------------------------


class TestGlslCallExtraction:
    """GLSL: call_expression extraction via generic handler."""

    SOURCE = """\
void main() { float x = sin(1.0); vec4 c = texture(tex, uv); }
"""

    def test_glsl_call(self):
        symbols = parse_file(self.SOURCE, "test.glsl", "glsl")
        assert len(symbols) >= 1
        sym = _find_symbol(symbols, "main")
        assert sym is not None, f"No 'main' symbol found. Symbols: {_symbol_names(symbols)}"
        assert "sin" in sym.calls, f"Expected 'sin' in calls, got: {sym.calls}"
        assert "texture" in sym.calls, f"Expected 'texture' in calls, got: {sym.calls}"


# ---------------------------------------------------------------------------
# Call extraction tests — HLSL
# ---------------------------------------------------------------------------


class TestHlslCallExtraction:
    """HLSL: call_expression extraction via generic handler."""

    SOURCE = """\
float4 main() : SV_Target { return float4(1,0,0,1); }
"""

    def test_hlsl_call(self):
        symbols = parse_file(self.SOURCE, "test.hlsl", "hlsl")
        assert len(symbols) >= 1
        sym = _find_symbol(symbols, "main")
        assert sym is not None, f"No 'main' symbol found. Symbols: {_symbol_names(symbols)}"
        assert "float4" in sym.calls, f"Expected 'float4' in calls, got: {sym.calls}"


# ---------------------------------------------------------------------------
# Complexity extras tests — Erlang
# ---------------------------------------------------------------------------


class TestErlangCaseComplexity:
    """Erlang: case_expr adds to cyclomatic complexity."""

    SOURCE = """\
-module(test).
f(X) -> case X of 1 -> ok; _ -> error end.
"""

    def test_erlang_case_complexity(self):
        node = _find_function_node(self.SOURCE, "erlang", "fun_decl")
        assert node is not None, "No fun_decl node found in Erlang source"
        result = compute_complexity(node, "erlang")
        assert result["cyclomatic"] > 1, (
            f"Expected cyclomatic > 1 for Erlang case, got: {result['cyclomatic']}"
        )


# ---------------------------------------------------------------------------
# Complexity extras tests — Scala
# ---------------------------------------------------------------------------


class TestScalaMatchComplexity:
    """Scala: match_expression adds to cyclomatic complexity."""

    SOURCE = """\
def f(x: Int) = x match { case 1 => 2; case _ => 3 }
"""

    def test_scala_match_complexity(self):
        node = _find_function_node(self.SOURCE, "scala", "function_definition")
        assert node is not None, "No function_definition node found in Scala source"
        result = compute_complexity(node, "scala")
        assert result["cyclomatic"] > 1, (
            f"Expected cyclomatic > 1 for Scala match, got: {result['cyclomatic']}"
        )


# ---------------------------------------------------------------------------
# Complexity extras tests — Haskell
# ---------------------------------------------------------------------------


class TestHaskellCaseComplexity:
    """Haskell: alternative nodes in case expression add to cyclomatic complexity."""

    SOURCE = """\
f x = case x of
  1 -> 2
  _ -> 3
"""

    def test_haskell_case_complexity(self):
        node = _find_function_node(self.SOURCE, "haskell", "function")
        assert node is not None, "No function node found in Haskell source"
        result = compute_complexity(node, "haskell")
        assert result["cyclomatic"] > 1, (
            f"Expected cyclomatic > 1 for Haskell case, got: {result['cyclomatic']}"
        )


# ---------------------------------------------------------------------------
# Complexity extras tests — Lua
# ---------------------------------------------------------------------------


class TestLuaRepeatComplexity:
    """Lua: repeat_statement adds to cyclomatic complexity."""

    SOURCE = """\
function f(x) repeat x = x - 1 until x == 0 end
"""

    def test_lua_repeat_complexity(self):
        node = _find_function_node(self.SOURCE, "lua", "function_declaration")
        assert node is not None, "No function_declaration node found in Lua source"
        result = compute_complexity(node, "lua")
        assert result["cyclomatic"] > 1, (
            f"Expected cyclomatic > 1 for Lua repeat, got: {result['cyclomatic']}"
        )
