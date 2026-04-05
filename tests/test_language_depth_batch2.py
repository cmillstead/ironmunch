"""Tests for language depth batch 2: import + call extraction for Phase 4 languages.

Verifies import and call extraction for fortran, v, gleam, cuda, odin, gdscript, ada, pascal, matlab.
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
# Fortran: imports (use) and calls (call)
# ---------------------------------------------------------------------------


class TestFortranImportAndCall:
    """Fortran: use_statement inside subroutine wrapper + subroutine_call."""

    SOURCE = """\
subroutine hello()
  use iso_fortran_env
  call greet()
end subroutine
"""

    def test_fortran_import_and_call(self):
        symbols = parse_file(self.SOURCE, "test.f90", "fortran")
        assert len(symbols) >= 1
        sym = _find_symbol(symbols, "hello")
        assert sym is not None, f"No 'hello' symbol found. Symbols: {_symbol_names(symbols)}"
        assert "iso_fortran_env" in sym.imports, f"Expected 'iso_fortran_env' in imports, got: {sym.imports}"
        assert "greet" in sym.calls, f"Expected 'greet' in calls, got: {sym.calls}"


# ---------------------------------------------------------------------------
# V: imports (import_declaration) and calls (call_expression)
# ---------------------------------------------------------------------------


class TestVImportAndCall:
    """V: import_declaration with path field + call_expression with function field."""

    SOURCE = """\
import os
import math
fn hello() {
  println("hi")
}
"""

    def test_v_import_and_call(self):
        symbols = parse_file(self.SOURCE, "test.v", "v")
        assert len(symbols) >= 1
        sym = _find_symbol(symbols, "hello")
        assert sym is not None, f"No 'hello' symbol found. Symbols: {_symbol_names(symbols)}"
        assert "os" in sym.imports, f"Expected 'os' in imports, got: {sym.imports}"
        assert "math" in sym.imports, f"Expected 'math' in imports, got: {sym.imports}"
        assert "println" in sym.calls, f"Expected 'println' in calls, got: {sym.calls}"


# ---------------------------------------------------------------------------
# Gleam: imports (import) and calls (function_call with field_access)
# ---------------------------------------------------------------------------


class TestGleamImportAndCall:
    """Gleam: import → module field + function_call with field_access for qualified calls."""

    SOURCE = """\
import gleam/io
pub fn hello() {
  io.println("hi")
}
"""

    def test_gleam_import_and_call(self):
        symbols = parse_file(self.SOURCE, "test.gleam", "gleam")
        assert len(symbols) >= 1
        sym = _find_symbol(symbols, "hello")
        assert sym is not None, f"No 'hello' symbol found. Symbols: {_symbol_names(symbols)}"
        assert "gleam/io" in sym.imports, f"Expected 'gleam/io' in imports, got: {sym.imports}"
        assert "io.println" in sym.calls, f"Expected 'io.println' in calls, got: {sym.calls}"


# ---------------------------------------------------------------------------
# CUDA: imports (preproc_include) and calls (call_expression) — reuses C extractors
# ---------------------------------------------------------------------------


class TestCudaImportAndCall:
    """CUDA: same as C — preproc_include + call_expression."""

    SOURCE = """\
#include <stdio.h>
void hello() { printf("hi"); }
"""

    def test_cuda_import_and_call(self):
        symbols = parse_file(self.SOURCE, "test.cu", "cuda")
        assert len(symbols) >= 1
        sym = _find_symbol(symbols, "hello")
        assert sym is not None, f"No 'hello' symbol found. Symbols: {_symbol_names(symbols)}"
        assert "stdio.h" in sym.imports, f"Expected 'stdio.h' in imports, got: {sym.imports}"
        assert "printf" in sym.calls, f"Expected 'printf' in calls, got: {sym.calls}"


# ---------------------------------------------------------------------------
# Odin: imports (import_declaration) and calls (call_expression)
# ---------------------------------------------------------------------------


class TestOdinImportAndCall:
    """Odin: import_declaration → string → string_content + call_expression (generic)."""

    SOURCE = """\
package main
import "core:fmt"
hello :: proc() {
  fmt.println("hi")
}
"""

    def test_odin_import_and_call(self):
        symbols = parse_file(self.SOURCE, "test.odin", "odin")
        assert len(symbols) >= 1
        sym = _find_symbol(symbols, "hello")
        assert sym is not None, f"No 'hello' symbol found. Symbols: {_symbol_names(symbols)}"
        assert "core:fmt" in sym.imports, f"Expected 'core:fmt' in imports, got: {sym.imports}"
        assert "println" in sym.calls, f"Expected 'println' in calls, got: {sym.calls}"


# ---------------------------------------------------------------------------
# GDScript: calls only (call node with first child identifier)
# ---------------------------------------------------------------------------


class TestGdscriptCall:
    """GDScript: call → first child is identifier (callee)."""

    SOURCE = """\
func hello():
  print("hi")
  greet()
"""

    def test_gdscript_call(self):
        symbols = parse_file(self.SOURCE, "test.gd", "gdscript")
        assert len(symbols) >= 1
        sym = _find_symbol(symbols, "hello")
        assert sym is not None, f"No 'hello' symbol found. Symbols: {_symbol_names(symbols)}"
        assert "print" in sym.calls, f"Expected 'print' in calls, got: {sym.calls}"
        assert "greet" in sym.calls, f"Expected 'greet' in calls, got: {sym.calls}"


# ---------------------------------------------------------------------------
# Ada: imports only (with_clause inside compilation_unit wrapper)
# ---------------------------------------------------------------------------


class TestAdaImport:
    """Ada: compilation_unit wrapper → with_clause → selected_component/identifier."""

    SOURCE = """\
with Ada.Text_IO;
with Ada.Integer_Text_IO;
procedure Hello is
begin
  null;
end Hello;
"""

    def test_ada_import(self):
        symbols = parse_file(self.SOURCE, "test.adb", "ada")
        assert len(symbols) >= 1
        # Check imports on any symbol (Ada procedure is inside compilation_unit)
        has_text_io = any("Ada.Text_IO" in s.imports for s in symbols)
        has_int_io = any("Ada.Integer_Text_IO" in s.imports for s in symbols)
        assert has_text_io, f"No symbol has Ada.Text_IO in imports. Symbols: {[(s.name, s.imports) for s in symbols]}"
        assert has_int_io, f"No symbol has Ada.Integer_Text_IO in imports. Symbols: {[(s.name, s.imports) for s in symbols]}"


# ---------------------------------------------------------------------------
# Pascal: imports only (declUses inside program wrapper)
# ---------------------------------------------------------------------------


class TestPascalImport:
    """Pascal: program wrapper → declUses → moduleName → identifier."""

    SOURCE = """\
program Test;
uses SysUtils;
procedure Hello;
begin
end;
begin
end.
"""

    def test_pascal_import(self):
        symbols = parse_file(self.SOURCE, "test.pas", "pascal")
        assert len(symbols) >= 1
        # Check imports on any symbol (Pascal uses are inside program wrapper)
        has_sysutils = any("SysUtils" in s.imports for s in symbols)
        assert has_sysutils, f"No symbol has SysUtils in imports. Symbols: {[(s.name, s.imports) for s in symbols]}"


# ---------------------------------------------------------------------------
# MATLAB: calls only (function_call with 'name' field)
# ---------------------------------------------------------------------------


class TestMatlabCall:
    """MATLAB: function_call → name field."""

    SOURCE = """\
function hello()
  disp("hi")
end
"""

    def test_matlab_call(self):
        symbols = parse_file(self.SOURCE, "test.m", "matlab")
        assert len(symbols) >= 1
        sym = _find_symbol(symbols, "hello")
        assert sym is not None, f"No 'hello' symbol found. Symbols: {_symbol_names(symbols)}"
        assert "disp" in sym.calls, f"Expected 'disp' in calls, got: {sym.calls}"
