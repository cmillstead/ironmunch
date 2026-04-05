"""Tests for language depth batch 1: import extraction for 7 languages + call extraction for D and ObjC.

Verifies import and call extraction for haskell, nim, julia, elm, d, ocaml, fsharp, and objc.
"""

from codesight_mcp.parser.extractor import parse_file


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


# ---------------------------------------------------------------------------
# Import extraction tests
# ---------------------------------------------------------------------------


class TestHaskellImportExtraction:
    """Haskell: qualified and plain imports."""

    SOURCE = """\
import qualified Data.Map as Map
import Foo.Bar
foo x = x
"""

    def test_haskell_import_extraction(self):
        symbols = parse_file(self.SOURCE, "test.hs", "haskell")
        assert len(symbols) >= 1
        sym = _find_symbol(symbols, "foo")
        assert sym is not None
        assert "Data.Map" in sym.imports
        assert "Foo.Bar" in sym.imports


class TestNimImportExtraction:
    """Nim: import and include statements."""

    SOURCE = """\
import std/strutils
include othermod
proc hello() = discard
"""

    def test_nim_import_extraction(self):
        symbols = parse_file(self.SOURCE, "test.nim", "nim")
        assert len(symbols) >= 1
        sym = _find_symbol(symbols, "hello")
        assert sym is not None
        assert "std/strutils" in sym.imports
        assert "othermod" in sym.imports


class TestJuliaImportExtraction:
    """Julia: using and import statements."""

    SOURCE = """\
using LinearAlgebra
import Base.Iterators: take
function hello() end
"""

    def test_julia_import_extraction(self):
        symbols = parse_file(self.SOURCE, "test.jl", "julia")
        assert len(symbols) >= 1
        sym = _find_symbol(symbols, "hello")
        assert sym is not None
        assert "LinearAlgebra" in sym.imports
        assert "Base.Iterators" in sym.imports

    def test_julia_dotted_import(self):
        """Julia: dotted module paths without selective import (import Base.Iterators)."""
        source = "import Base.Iterators\nusing LinearAlgebra.BLAS\nfunction hello() end\n"
        symbols = parse_file(source, "test.jl", "julia")
        sym = _find_symbol(symbols, "hello")
        assert sym is not None
        assert "Base.Iterators" in sym.imports
        assert "LinearAlgebra.BLAS" in sym.imports


class TestElmImportExtraction:
    """Elm: import clauses."""

    SOURCE = """\
import Html exposing (text)
import Foo.Bar as Bar
hello = 1
"""

    def test_elm_import_extraction(self):
        symbols = parse_file(self.SOURCE, "test.elm", "elm")
        assert len(symbols) >= 1
        sym = _find_symbol(symbols, "hello")
        assert sym is not None
        assert "Html" in sym.imports
        assert "Foo.Bar" in sym.imports


class TestDImportAndCallExtraction:
    """D: import declarations and call expressions."""

    SOURCE = """\
import std.stdio;
void hello(){ writeln("x"); foo.bar(1); }
"""

    def test_d_import_and_call_extraction(self):
        symbols = parse_file(self.SOURCE, "test.d", "d")
        assert len(symbols) >= 1
        sym = _find_symbol(symbols, "hello")
        assert sym is not None
        assert "std.stdio" in sym.imports
        assert "writeln" in sym.calls
        assert "foo.bar" in sym.calls


class TestOcamlOpenExtraction:
    """OCaml: open module statements."""

    SOURCE = """\
open Core
let hello x = x
"""

    def test_ocaml_open_extraction(self):
        symbols = parse_file(self.SOURCE, "test.ml", "ocaml")
        assert len(symbols) >= 1
        sym = _find_symbol(symbols, "hello")
        assert sym is not None
        assert "Core" in sym.imports


class TestFsharpOpenExtraction:
    """F#: open statements."""

    SOURCE = """\
open System.IO
module Foo =
  let bar x = x
"""

    def test_fsharp_open_extraction(self):
        symbols = parse_file(self.SOURCE, "test.fsx", "fsharp")
        assert len(symbols) >= 1
        # Find any symbol that has imports
        has_imports = any("System.IO" in s.imports for s in symbols)
        assert has_imports, f"No symbol has System.IO in imports. Symbols: {[(s.name, s.imports) for s in symbols]}"


class TestObjcImportAndCallExtraction:
    """ObjC: #import and message expressions."""

    SOURCE = """\
#import <Foundation/Foundation.h>
@implementation Foo
- (void)bar { [obj doThing:1 with:2]; }
@end
"""

    def test_objc_import_and_call_extraction(self):
        symbols = parse_file(self.SOURCE, "test.mm", "objc")
        assert len(symbols) >= 1
        # Check imports on any symbol
        has_import = any("Foundation/Foundation.h" in s.imports for s in symbols)
        assert has_import, f"No symbol has Foundation/Foundation.h. Symbols: {[(s.name, s.imports) for s in symbols]}"
        # Check calls on bar method
        bar_sym = _find_symbol(symbols, "bar")
        assert bar_sym is not None, f"No 'bar' symbol found. Symbols: {_symbol_names(symbols)}"
        assert "doThing:with:" in bar_sym.calls, f"Expected 'doThing:with:' in calls, got: {bar_sym.calls}"
