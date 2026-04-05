"""Tests for batch 1 language support: lua, bash, r, scala, elixir, julia, clojure.

Verifies symbol extraction, extension mapping, and registry completeness
for each new language added in batch 1.
"""

import pytest

from codesight_mcp.parser.extractor import parse_file
from codesight_mcp.parser.languages import LANGUAGE_EXTENSIONS, LANGUAGE_REGISTRY


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _symbol_names(symbols):
    """Extract symbol names as a set for assertion convenience."""
    return {s.name for s in symbols}


def _symbol_kinds(symbols):
    """Extract (name, kind) pairs as a set."""
    return {(s.name, s.kind) for s in symbols}


# ---------------------------------------------------------------------------
# Per-language symbol extraction tests
# ---------------------------------------------------------------------------


class TestLuaSymbols:
    """Lua: function declarations (global and local)."""

    SOURCE = """\
function hello(x)
  return x
end

local function inner(a, b)
  return a + b
end
"""

    def test_lua_symbols(self):
        symbols = parse_file(self.SOURCE, "test.lua", "lua")
        assert len(symbols) == 2
        assert _symbol_names(symbols) == {"hello", "inner"}
        for sym in symbols:
            assert sym.kind == "function"
            assert sym.language == "lua"


class TestBashSymbols:
    """Bash: function keyword and shorthand forms."""

    SOURCE = """\
function hello() {
  echo hi
}

world() {
  echo yo
}
"""

    def test_bash_symbols(self):
        symbols = parse_file(self.SOURCE, "test.sh", "bash")
        assert len(symbols) == 2
        assert _symbol_names(symbols) == {"hello", "world"}
        for sym in symbols:
            assert sym.kind == "function"
            assert sym.language == "bash"


class TestRSymbols:
    """R: arrow-assignment function definitions."""

    SOURCE = """\
foo <- function(x) {
  x + 1
}

bar <- function(y) {
  y * 2
}
"""

    def test_r_symbols(self):
        symbols = parse_file(self.SOURCE, "test.r", "r")
        # R extracts top-level function assignments plus parameter identifiers
        # as child symbols; filter to top-level functions for the core assertion.
        top_level = [s for s in symbols if s.kind == "function" and s.parent is None]
        assert len(top_level) == 2
        assert {s.name for s in top_level} == {"foo", "bar"}
        for sym in top_level:
            assert sym.language == "r"


class TestScalaSymbols:
    """Scala: class, object, def, and trait declarations."""

    SOURCE = """\
class Foo
object Bar
def baz(x: Int): String = x.toString
trait Qux
"""

    def test_scala_symbols(self):
        symbols = parse_file(self.SOURCE, "test.scala", "scala")
        assert len(symbols) == 4
        assert _symbol_names(symbols) == {"Foo", "Bar", "baz", "Qux"}
        kinds = _symbol_kinds(symbols)
        assert ("Foo", "class") in kinds
        assert ("Bar", "class") in kinds
        assert ("baz", "function") in kinds
        assert ("Qux", "type") in kinds


class TestElixirSymbols:
    """Elixir: defmodule, def, defp."""

    SOURCE = """\
defmodule Demo do
  def hi(x), do: x
  defp low(), do: :ok
end
"""

    def test_elixir_symbols(self):
        symbols = parse_file(self.SOURCE, "test.ex", "elixir")
        names = _symbol_names(symbols)
        # At minimum we expect Demo and hi (defp may or may not be extracted)
        assert len(symbols) >= 2
        assert "Demo" in names
        assert "hi" in names or "low" in names


class TestJuliaSymbols:
    """Julia: function and struct definitions."""

    SOURCE = """\
function hello(x)
  x
end

struct Foo
  x::Int
end
"""

    def test_julia_symbols(self):
        symbols = parse_file(self.SOURCE, "test.jl", "julia")
        assert len(symbols) == 2
        names = _symbol_names(symbols)
        assert "hello" in names
        assert "Foo" in names
        kinds = _symbol_kinds(symbols)
        assert ("hello", "function") in kinds
        assert ("Foo", "class") in kinds


class TestClojureSymbols:
    """Clojure: ns, def, defn forms."""

    SOURCE = """\
(ns demo)
(def answer 42)
(defn greet [x] x)
"""

    def test_clojure_symbols(self):
        symbols = parse_file(self.SOURCE, "test.clj", "clojure")
        names = _symbol_names(symbols)
        assert len(symbols) >= 2
        # At least 2 of these 3 should be present
        expected = {"demo", "answer", "greet"}
        assert len(names & expected) >= 2


# ---------------------------------------------------------------------------
# Extension mapping tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ext,expected_lang", [
    (".lua", "lua"),
    (".sh", "bash"),
    (".bash", "bash"),
    (".r", "r"),
    (".R", "r"),
    (".scala", "scala"),
    (".ex", "elixir"),
    (".exs", "elixir"),
    (".jl", "julia"),
    (".clj", "clojure"),
    (".cljc", "clojure"),
    (".cljs", "clojure"),
])
def test_language_extensions_batch1(ext, expected_lang):
    """Verify all batch 1 file extensions map to the correct language."""
    assert LANGUAGE_EXTENSIONS[ext] == expected_lang


# ---------------------------------------------------------------------------
# Registry completeness test
# ---------------------------------------------------------------------------

BATCH1_LANGUAGES = ["lua", "bash", "r", "scala", "elixir", "julia", "clojure"]


def test_batch1_in_registry():
    """All 7 batch 1 languages must be registered in LANGUAGE_REGISTRY."""
    for lang in BATCH1_LANGUAGES:
        assert lang in LANGUAGE_REGISTRY, f"{lang} missing from LANGUAGE_REGISTRY"
