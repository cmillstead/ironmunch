"""Tests for batch 2 language support: nim, haskell, erlang, zig, d, objc, ocaml, fsharp, elm.

Verifies symbol extraction, extension mapping, and registry completeness
for each new language added in batch 2.
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


class TestNimSymbols:
    """Nim: proc declarations."""

    SOURCE = """\
proc hello(x: int): int = x
"""

    def test_nim_symbols(self):
        symbols = parse_file(self.SOURCE, "test.nim", "nim")
        assert len(symbols) >= 1
        names = _symbol_names(symbols)
        assert "hello" in names
        kinds = _symbol_kinds(symbols)
        assert ("hello", "function") in kinds


class TestHaskellSymbols:
    """Haskell: function definitions and data declarations."""

    SOURCE = """\
module Main where
foo :: Int -> Int
foo x = x + 1
data Color = Red | Blue
"""

    def test_haskell_symbols(self):
        symbols = parse_file(self.SOURCE, "test.hs", "haskell")
        names = _symbol_names(symbols)
        assert "foo" in names
        assert "Color" in names
        # Type signatures must NOT be extracted as symbols
        assert "Int" not in names
        kinds = _symbol_kinds(symbols)
        assert ("foo", "function") in kinds
        assert ("Color", "class") in kinds or ("Color", "type") in kinds


class TestHaskellNoSignatureFalsePositives:
    """Haskell: type signatures must not produce false-positive symbols."""

    SOURCE = """\
bar :: String -> String
bar x = x
"""

    def test_haskell_no_signature_false_positives(self):
        symbols = parse_file(self.SOURCE, "test.hs", "haskell")
        names = _symbol_names(symbols)
        assert "bar" in names
        assert "String" not in names


class TestErlangSymbols:
    """Erlang: module attribute and function definitions."""

    SOURCE = """\
-module(demo).
hello(X) -> X + 1.
world(Y) -> Y * 2.
"""

    def test_erlang_symbols(self):
        symbols = parse_file(self.SOURCE, "test.erl", "erlang")
        names = _symbol_names(symbols)
        assert "demo" in names
        assert "hello" in names
        assert "world" in names
        kinds = _symbol_kinds(symbols)
        assert ("demo", "class") in kinds
        assert ("hello", "function") in kinds
        assert ("world", "function") in kinds


class TestZigSymbols:
    """Zig: fn and const struct declarations."""

    SOURCE = """\
fn hello() void {}
const Foo = struct { x: i32, };
"""

    def test_zig_symbols(self):
        symbols = parse_file(self.SOURCE, "test.zig", "zig")
        names = _symbol_names(symbols)
        assert "hello" in names
        assert "Foo" in names
        kinds = _symbol_kinds(symbols)
        assert ("hello", "function") in kinds
        assert ("Foo", "class") in kinds


class TestDSymbols:
    """D: function, class, and struct declarations."""

    SOURCE = """\
void hello(int x) { }
class Foo { int x; }
struct Bar { int y; }
"""

    def test_d_symbols(self):
        symbols = parse_file(self.SOURCE, "test.d", "d")
        names = _symbol_names(symbols)
        assert "hello" in names
        assert "Foo" in names
        assert "Bar" in names
        kinds = _symbol_kinds(symbols)
        assert ("hello", "function") in kinds
        assert ("Foo", "class") in kinds
        assert ("Bar", "type") in kinds or ("Bar", "class") in kinds


class TestObjcSymbols:
    """Objective-C: interface, implementation, methods, and multi-part selectors."""

    SOURCE = """\
@interface Foo : NSObject
- (void)hello;
- (void)setValue:(int)x other:(int)y;
@end
@implementation Foo
- (void)hello { }
@end
"""

    def test_objc_symbols(self):
        symbols = parse_file(self.SOURCE, "test.mm", "objc")
        names = _symbol_names(symbols)
        assert "Foo" in names
        assert "hello" in names
        kinds = _symbol_kinds(symbols)
        assert ("Foo", "class") in kinds
        # Multi-part selector must preserve full name with colons
        assert "setValue:other:" in names


class TestObjcMultipartSelector:
    """Objective-C: multi-part selectors must include all keyword parts with colons."""

    SOURCE = """\
@interface Bar : NSObject
- (void)doSomething:(int)x with:(int)y and:(int)z;
@end
"""

    def test_objc_multipart_selector(self):
        symbols = parse_file(self.SOURCE, "test.mm", "objc")
        names = _symbol_names(symbols)
        assert "doSomething:with:and:" in names


class TestOcamlSymbols:
    """OCaml: let bindings, module definitions, and type declarations."""

    SOURCE = """\
let hello x = x + 1
module Foo = struct end
type color = Red | Blue
"""

    def test_ocaml_symbols(self):
        symbols = parse_file(self.SOURCE, "test.ml", "ocaml")
        names = _symbol_names(symbols)
        assert "hello" in names
        assert "Foo" in names
        assert "color" in names
        kinds = _symbol_kinds(symbols)
        assert ("hello", "function") in kinds
        assert ("Foo", "class") in kinds
        assert ("color", "type") in kinds


class TestFsharpSymbols:
    """F#: let bindings, module definitions, and type declarations."""

    SOURCE = """\
let hello x = x + 1
module Foo =
  let bar = 1
type Record = { X: int }
"""

    def test_fsharp_symbols(self):
        symbols = parse_file(self.SOURCE, "test.fs", "fsharp")
        names = _symbol_names(symbols)
        assert "hello" in names
        assert "Foo" in names
        assert "bar" in names
        assert "Record" in names
        kinds = _symbol_kinds(symbols)
        assert ("hello", "function") in kinds
        assert ("Foo", "class") in kinds
        assert ("bar", "method") in kinds
        assert ("Record", "type") in kinds


class TestElmSymbols:
    """Elm: function definitions and type declarations."""

    SOURCE = """\
module Main exposing (..)
hello x = x + 1
type Msg = Click | Reset
"""

    def test_elm_symbols(self):
        symbols = parse_file(self.SOURCE, "test.elm", "elm")
        names = _symbol_names(symbols)
        assert "hello" in names
        assert "Msg" in names
        kinds = _symbol_kinds(symbols)
        assert ("hello", "function") in kinds
        assert ("Msg", "type") in kinds


# ---------------------------------------------------------------------------
# Extension mapping tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ext,expected_lang", [
    (".nim", "nim"),
    (".nims", "nim"),
    (".hs", "haskell"),
    (".erl", "erlang"),
    (".hrl", "erlang"),
    (".zig", "zig"),
    (".d", "d"),
    (".mm", "objc"),
    (".ml", "ocaml"),
    (".mli", "ocaml"),
    (".fs", "fsharp"),
    (".fsi", "fsharp"),
    (".fsx", "fsharp"),
    (".elm", "elm"),
])
def test_language_extensions_batch2(ext, expected_lang):
    """Verify all batch 2 file extensions map to the correct language."""
    assert LANGUAGE_EXTENSIONS[ext] == expected_lang


# ---------------------------------------------------------------------------
# Registry completeness test
# ---------------------------------------------------------------------------

BATCH2_LANGUAGES = ["nim", "haskell", "erlang", "zig", "d", "objc", "ocaml", "fsharp", "elm"]


def test_batch2_in_registry():
    """All 9 batch 2 languages must be registered in LANGUAGE_REGISTRY."""
    for lang in BATCH2_LANGUAGES:
        assert lang in LANGUAGE_REGISTRY, f"{lang} missing from LANGUAGE_REGISTRY"
