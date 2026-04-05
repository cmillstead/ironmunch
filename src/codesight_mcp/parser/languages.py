"""Language registry with LanguageSpec definitions for all supported languages."""

from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class LanguageSpec:
    """Specification for extracting symbols from a language's AST."""
    # tree-sitter language name (for tree-sitter-language-pack)
    ts_language: str

    # Node types that represent extractable symbols
    # Maps node_type -> symbol kind
    symbol_node_types: dict[str, str]

    # How to extract the symbol name from a node
    # Maps node_type -> child field name containing the name
    name_fields: dict[str, str]

    # How to extract parameters/signature beyond the name
    # Maps node_type -> child field name for parameters
    param_fields: dict[str, str]

    # Return type extraction (if language supports it)
    # Maps node_type -> child field name for return type
    return_type_fields: dict[str, str]

    # Docstring extraction strategy
    # "next_sibling_string" = Python (expression_statement after def)
    # "first_child_comment" = JS/TS (/** */ before function)
    # "preceding_comment" = Go/Rust/Java (// or /* */ before decl)
    docstring_strategy: str

    # Decorator/attribute node type (if any)
    decorator_node_type: Optional[str]

    # Node types that indicate nesting (methods inside classes)
    container_node_types: list[str]

    # Additional extraction: constants, type aliases
    constant_patterns: list[str]   # Node types for constants
    type_patterns: list[str]       # Node types for type definitions

    # Relationship tracking: AST node types for call graphs, imports, inheritance
    call_node_types: list[str] = field(default_factory=list)          # Function/method call node types
    import_node_types: list[str] = field(default_factory=list)        # Import statement node types
    inheritance_fields: list[str] = field(default_factory=list)       # AST fields for superclass/parent refs
    implementation_fields: list[str] = field(default_factory=list)    # AST fields for interface implementations

    # Per-language import extraction: (node, source_bytes) -> list[str]
    # Each language provides its own logic for extracting import names from an import node.
    extract_import: Optional[Callable] = None

    # Per-language type name collection: (child_node, source_bytes, extract_type_identifier_fn) -> list[str]
    # Each language provides its own logic for collecting type names from inheritance fields.
    collect_type_names: Optional[Callable] = None

    # Per-language name extraction: (node, source_bytes) -> Optional[str]
    # Override default name extraction for specific node types.
    extract_name: Optional[Callable] = None

    # Per-language kind override: (node, source_bytes, default_kind) -> str
    # Override the static kind from symbol_node_types when a single node type
    # maps to multiple symbol kinds (e.g., Elixir 'call' → class for defmodule, function for def).
    resolve_kind: Optional[Callable] = None

    # Per-language call target extraction: (node, spec, source_bytes, calls) -> bool
    # Override default call collection for specific call node types.
    # Returns True if the call was handled, False to fall through to default logic.
    extract_call_target: Optional[Callable] = None

    # When True, _extract_symbol() sets signature = name instead of calling
    # _build_signature(). Used by config languages (yaml, json, toml, html, xml)
    # to prevent secret values from leaking into signatures.
    signature_from_name: bool = False


def _strip_quotes(text: str) -> str:
    """Strip quotes from a string literal."""
    text = text.strip()
    if text.startswith('"""') and text.endswith('"""'):
        return text[3:-3].strip()
    if text.startswith("'''") and text.endswith("'''"):
        return text[3:-3].strip()
    if text.startswith('"') and text.endswith('"'):
        return text[1:-1].strip()
    if text.startswith("'") and text.endswith("'"):
        return text[1:-1].strip()
    return text


# ---------------------------------------------------------------------------
# Per-language import extraction functions
# Each takes (node, source_bytes) and returns list[str] of import names.
# ---------------------------------------------------------------------------

def _extract_import_python_import_statement(node, source_bytes: bytes) -> list[str]:
    """Python: import foo, import foo.bar."""
    imports = []
    # Check for source field (JS/TS style) — not applicable to Python import_statement
    # but the old code checked it for both Python and JS/TS since they share the node type.
    source_node = node.child_by_field_name("source")
    if source_node:
        text = source_bytes[source_node.start_byte:source_node.end_byte].decode("utf-8")
        imports.append(_strip_quotes(text))
    else:
        for named_child in node.named_children:
            if named_child.type in ("dotted_name", "aliased_import"):
                if named_child.type == "aliased_import":
                    name_node = named_child.child_by_field_name("name")
                    if name_node:
                        imports.append(
                            source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8")
                        )
                else:
                    imports.append(
                        source_bytes[named_child.start_byte:named_child.end_byte].decode("utf-8")
                    )
    return imports


def _extract_import_python_from(node, source_bytes: bytes) -> list[str]:
    """Python: from foo.bar import baz."""
    module_node = node.child_by_field_name("module_name")
    if module_node:
        return [source_bytes[module_node.start_byte:module_node.end_byte].decode("utf-8")]
    return []


def _extract_import_js_ts(node, source_bytes: bytes) -> list[str]:
    """JS/TS: import ... from 'source'."""
    source_node = node.child_by_field_name("source")
    if source_node:
        text = source_bytes[source_node.start_byte:source_node.end_byte].decode("utf-8")
        return [_strip_quotes(text)]
    return []


def _extract_import_go(node, source_bytes: bytes) -> list[str]:
    """Go: import 'fmt' or grouped imports."""
    imports = []
    for named_child in node.named_children:
        if named_child.type == "import_spec":
            path_node = named_child.child_by_field_name("path")
            if path_node:
                text = source_bytes[path_node.start_byte:path_node.end_byte].decode("utf-8")
                imports.append(_strip_quotes(text))
        elif named_child.type == "import_spec_list":
            for spec_child in named_child.named_children:
                if spec_child.type == "import_spec":
                    path_node = spec_child.child_by_field_name("path")
                    if path_node:
                        text = source_bytes[path_node.start_byte:path_node.end_byte].decode("utf-8")
                        imports.append(_strip_quotes(text))
    return imports


def _extract_import_java(node, source_bytes: bytes) -> list[str]:
    """Java: import java.util.List."""
    imports = []
    for named_child in node.named_children:
        if named_child.type == "scoped_identifier":
            imports.append(
                source_bytes[named_child.start_byte:named_child.end_byte].decode("utf-8")
            )
    return imports


def _extract_import_rust(node, source_bytes: bytes) -> list[str]:
    """Rust: use std::collections::HashMap."""
    for named_child in node.named_children:
        if named_child.type not in ("visibility_modifier",):
            text = source_bytes[named_child.start_byte:named_child.end_byte].decode("utf-8")
            return [text]
    return []


def _extract_import_php(node, source_bytes: bytes) -> list[str]:
    """PHP: use App\\Models\\User."""
    imports = []
    for named_child in node.named_children:
        if named_child.type in ("namespace_use_clause", "namespace_use_group"):
            text = source_bytes[named_child.start_byte:named_child.end_byte].decode("utf-8")
            imports.append(text)
    return imports


def _extract_import_c_include(node, source_bytes: bytes) -> list[str]:
    """C/C++: #include <stdio.h> or #include 'myheader.h'."""
    path_node = node.child_by_field_name("path")
    if path_node:
        text = source_bytes[path_node.start_byte:path_node.end_byte].decode("utf-8")
        text = text.strip('<>"')
        return [text]
    return []


def _extract_import_csharp_using(node, source_bytes: bytes) -> list[str]:
    """C#: using System.Collections.Generic."""
    for named_child in node.named_children:
        if named_child.type in ("qualified_name", "identifier", "name"):
            text = source_bytes[named_child.start_byte:named_child.end_byte].decode("utf-8")
            return [text]
    return []


def _extract_import_cpp_using(node, source_bytes: bytes) -> list[str]:
    """C++: using namespace std; or using std::string."""
    for named_child in node.named_children:
        text = source_bytes[named_child.start_byte:named_child.end_byte].decode("utf-8")
        return [text]
    return []


def _extract_import_swift(node, source_bytes: bytes) -> list[str]:
    """Swift: import Foundation."""
    for named_child in node.named_children:
        if named_child.type in ("identifier", "simple_identifier"):
            text = source_bytes[named_child.start_byte:named_child.end_byte].decode("utf-8")
            return [text]
    return []


def _extract_import_kotlin(node, source_bytes: bytes) -> list[str]:
    """Kotlin: import kotlin.collections.List."""
    for named_child in node.named_children:
        if named_child.type in ("identifier", "qualified_identifier"):
            text = source_bytes[named_child.start_byte:named_child.end_byte].decode("utf-8")
            return [text]
    return []


def _extract_import_dart(node, source_bytes: bytes) -> list[str]:
    """Dart: import 'dart:core'; or import 'package:foo/bar.dart';"""
    # import_or_export -> library_import -> import_specification -> configurable_uri
    for child in node.named_children:
        if child.type == "library_import":
            for sub in child.named_children:
                if sub.type == "import_specification":
                    for spec_child in sub.named_children:
                        if spec_child.type == "configurable_uri":
                            text = source_bytes[spec_child.start_byte:spec_child.end_byte].decode("utf-8")
                            return [_strip_quotes(text)]
    return []


def _extract_import_perl(node, source_bytes: bytes) -> list[str]:
    """Perl: use Data::Dumper;"""
    for named_child in node.named_children:
        if named_child.type == "package":
            text = source_bytes[named_child.start_byte:named_child.end_byte].decode("utf-8")
            return [text]
    return []


def _extract_import_haskell(node, source_bytes: bytes) -> list[str]:
    """Haskell: import Data.Map, import qualified Data.Map as Map."""
    imports = []
    for child in node.named_children:
        if child.type == "import":
            module_node = child.child_by_field_name("module")
            if module_node:
                text = source_bytes[module_node.start_byte:module_node.end_byte].decode("utf-8")
                imports.append(text)
    return imports


def _extract_import_nim(node, source_bytes: bytes) -> list[str]:
    """Nim: import std/strutils, include othermod."""
    imports = []
    for child in node.named_children:
        if child.type == "expression_list":
            for expr in child.named_children:
                text = source_bytes[expr.start_byte:expr.end_byte].decode("utf-8")
                imports.append(text)
        elif child.type in ("infix_expression", "identifier"):
            text = source_bytes[child.start_byte:child.end_byte].decode("utf-8")
            imports.append(text)
    return imports


def _extract_import_julia(node, source_bytes: bytes) -> list[str]:
    """Julia: using LinearAlgebra, import Base.Iterators: take, import Base.Iterators."""
    imports = []
    for child in node.named_children:
        if child.type == "identifier":
            imports.append(source_bytes[child.start_byte:child.end_byte].decode("utf-8"))
        elif child.type == "import_path":
            # Dotted imports: import Base.Iterators → import_path with identifier children
            imports.append(source_bytes[child.start_byte:child.end_byte].decode("utf-8"))
        elif child.type == "selected_import":
            # Selective imports: import Base.Iterators: take → selected_import → import_path
            path_node = child.child_by_field_name("path") or _find_child_by_type(child, "import_path")
            if path_node:
                imports.append(source_bytes[path_node.start_byte:path_node.end_byte].decode("utf-8"))
    return imports


def _find_child_by_type(node, child_type: str):
    """Find the first named child of the given type."""
    for child in node.named_children:
        if child.type == child_type:
            return child
    return None


def _extract_import_elm(node, source_bytes: bytes) -> list[str]:
    """Elm: import Html exposing (text), import Foo.Bar as Bar."""
    module_node = node.child_by_field_name("moduleName")
    if module_node:
        text = source_bytes[module_node.start_byte:module_node.end_byte].decode("utf-8")
        return [text]
    return []


def _extract_import_d(node, source_bytes: bytes) -> list[str]:
    """D: import std.stdio;"""
    imports = []
    for child in node.named_children:
        if child.type == "imported":
            for sub in child.named_children:
                if sub.type == "module_fqn":
                    parts = [
                        source_bytes[ident.start_byte:ident.end_byte].decode("utf-8")
                        for ident in sub.named_children
                        if ident.type == "identifier"
                    ]
                    if parts:
                        imports.append(".".join(parts))
    return imports


def _extract_import_ocaml(node, source_bytes: bytes) -> list[str]:
    """OCaml: open Core."""
    for child in node.named_children:
        if child.type not in ("open",):
            text = source_bytes[child.start_byte:child.end_byte].decode("utf-8")
            return [text]
    return []


def _extract_import_fsharp(node, source_bytes: bytes) -> list[str]:
    """F#: open System.IO."""
    for child in node.named_children:
        if child.type == "long_identifier":
            parts = [
                source_bytes[ident.start_byte:ident.end_byte].decode("utf-8")
                for ident in child.named_children
                if ident.type == "identifier"
            ]
            if parts:
                return [".".join(parts)]
    return []


def _make_import_dispatcher(handlers: dict[str, Callable]) -> Callable:
    """Create a single extract_import function that dispatches by node type."""
    def _extract(node, source_bytes: bytes) -> list[str]:
        handler = handlers.get(node.type)
        if handler:
            return handler(node, source_bytes)
        return []
    return _extract


# ---------------------------------------------------------------------------
# Per-language type name collection functions
# Each takes (child_node, source_bytes, extract_type_id_fn) and returns list[str].
# ---------------------------------------------------------------------------

def _collect_types_argument_list(child, source_bytes, extract_type_id):
    """Python argument_list: class Foo(Bar, Baz)."""
    result = []
    for arg in child.named_children:
        name = extract_type_id(arg, source_bytes)
        if name:
            result.append(name)
    return result


def _collect_types_class_heritage(child, source_bytes, extract_type_id):
    """JS/TS class_heritage: extends_clause and/or implements_clause."""
    result = []
    for clause in child.named_children:
        for type_child in clause.named_children:
            name = extract_type_id(type_child, source_bytes)
            if name:
                result.append(name)
    return result


def _collect_types_superclass(child, source_bytes, extract_type_id):
    """Java/Ruby superclass: directly contains a type_identifier."""
    result = []
    for type_child in child.named_children:
        name = extract_type_id(type_child, source_bytes)
        if name:
            result.append(name)
    return result


def _collect_types_super_interfaces(child, source_bytes, extract_type_id):
    """Java super_interfaces / interfaces: contains type_list."""
    result = []
    for type_child in child.named_children:
        if type_child.type == "type_list":
            for t in type_child.named_children:
                name = extract_type_id(t, source_bytes)
                if name:
                    result.append(name)
        else:
            name = extract_type_id(type_child, source_bytes)
            if name:
                result.append(name)
    return result


def _collect_types_named_children(child, source_bytes, extract_type_id):
    """Generic: extract identifiers from all named children.

    Used for: PHP base_clause, PHP class_interface_clause, Rust trait_bounds,
    C++ base_class_clause, C# base_list, Swift inheritance_specifier.
    """
    result = []
    for type_child in child.named_children:
        name = extract_type_id(type_child, source_bytes)
        if name:
            result.append(name)
    return result


def _collect_types_delegation_specifiers(child, source_bytes, extract_type_id):
    """Kotlin delegation_specifiers: class Foo : Bar(), Baz."""
    result = []
    for spec_child in child.named_children:
        if spec_child.type == "delegation_specifier":
            for type_child in spec_child.named_children:
                name = extract_type_id(type_child, source_bytes)
                if name:
                    result.append(name)
                    break
        else:
            name = extract_type_id(spec_child, source_bytes)
            if name:
                result.append(name)
    return result


def _make_type_collector(handlers: dict[str, Callable]) -> Callable:
    """Create a single collect_type_names function that dispatches by child node type."""
    def _collect(child, source_bytes, extract_type_id):
        handler = handlers.get(child.type)
        if handler:
            return handler(child, source_bytes, extract_type_id)
        # Fallback: try to extract identifiers from all named children
        result = []
        for type_child in child.named_children:
            name = extract_type_id(type_child, source_bytes)
            if name:
                result.append(name)
        return result
    return _collect


# ---------------------------------------------------------------------------
# Per-language name extraction functions
# Each takes (node, source_bytes) and returns Optional[str].
# ---------------------------------------------------------------------------

def _extract_name_c_cpp(node, source_bytes: bytes):
    """C/C++: function_definition uses declarator -> function_declarator -> declarator.
    type_definition uses declarator for the typedef name."""
    if node.type == "function_definition":
        decl = node.child_by_field_name("declarator")
        if decl:
            if decl.type == "function_declarator":
                name_node = decl.child_by_field_name("declarator")
                if name_node:
                    return source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8")
            elif decl.type == "pointer_declarator":
                for child in decl.named_children:
                    if child.type == "function_declarator":
                        name_node = child.child_by_field_name("declarator")
                        if name_node:
                            return source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8")
        return None

    if node.type == "type_definition":
        decl = node.child_by_field_name("declarator")
        if decl:
            return source_bytes[decl.start_byte:decl.end_byte].decode("utf-8")
        return None

    return None  # Not handled — fall through to default


def _extract_name_dart(node, source_bytes: bytes):
    """Dart: function_signature/method_signature — name is in nested identifier."""
    if node.type in ("function_signature", "method_signature"):
        sig = node
        if node.type == "method_signature":
            for child in node.named_children:
                if child.type == "function_signature":
                    sig = child
                    break
        name_node = sig.child_by_field_name("name")
        if name_node:
            return source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8")
        for child in sig.named_children:
            if child.type == "identifier":
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8")
        return None

    return None  # Not handled — fall through to default


def _extract_name_perl(node, source_bytes: bytes):
    """Perl: subroutine_declaration_statement uses bareword child.
    package_statement uses the package child."""
    if node.type == "subroutine_declaration_statement":
        for child in node.named_children:
            if child.type == "bareword":
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8")
        return None

    if node.type == "package_statement":
        packages = [c for c in node.named_children if c.type == "package"]
        if packages:
            return source_bytes[packages[-1].start_byte:packages[-1].end_byte].decode("utf-8")
        return None

    return None  # Not handled — fall through to default


def _extract_name_r(node, source_bytes: bytes):
    """R: binary_operator with <- / <<- / = assigns a name to the LHS identifier.
    Only extracts assignment operators with function_definition RHS."""
    if node.type == "binary_operator":
        # Only index function assignments, not plain value assignments like x <- 1
        rhs = node.child_by_field_name("rhs")
        if not rhs or rhs.type != "function_definition":
            return None
        # Verify operator is an assignment (<-, <<-, =), not +, ~, etc.
        operator = node.child_by_field_name("operator")
        if operator:
            op_text = source_bytes[operator.start_byte:operator.end_byte].decode("utf-8").strip()
            if op_text not in ("<-", "<<-", "="):
                return None
        lhs = node.child_by_field_name("lhs")
        if lhs and lhs.type == "identifier":
            return source_bytes[lhs.start_byte:lhs.end_byte].decode("utf-8")
        return None

    return None  # Not handled — fall through to default


def _resolve_kind_elixir(node, source_bytes: bytes, default_kind: str) -> str | None:
    """Elixir: defmodule → class, def/defp/defmacro → function, other calls → skip."""
    if node.type != "call":
        return default_kind
    children = node.named_children
    if not children or children[0].type != "identifier":
        return None  # Not a definition form — skip
    form = source_bytes[children[0].start_byte:children[0].end_byte].decode("utf-8")
    if form == "defmodule":
        return "class"
    if form in ("def", "defp", "defmacro"):
        return "function"
    return None  # Not a definition form — skip


def _resolve_kind_clojure(node, source_bytes: bytes, default_kind: str) -> str | None:
    """Clojure: defn/defmethod/defmulti → function, def/defonce → constant, defprotocol → class."""
    if node.type != "list_lit":
        return default_kind
    sym_children = [c for c in node.named_children if c.type == "sym_lit"]
    if not sym_children:
        return None
    first_text = source_bytes[sym_children[0].start_byte:sym_children[0].end_byte].decode("utf-8")
    _KIND_MAP = {
        "defn": "function", "defmethod": "function", "defmulti": "function",
        "defmacro": "function", "def": "constant", "defonce": "constant",
        "defprotocol": "class",
    }
    return _KIND_MAP.get(first_text)  # None for non-def forms → skip


def _extract_name_elixir(node, source_bytes: bytes):
    """Elixir: call nodes represent defmodule/def/defp/defmacro.
    First child identifier determines the form; name is in arguments."""
    if node.type != "call":
        return None

    children = node.named_children
    if not children or children[0].type != "identifier":
        return None

    form = source_bytes[children[0].start_byte:children[0].end_byte].decode("utf-8")

    if form == "defmodule":
        # Name is in arguments -> alias child
        args = next((c for c in children if c.type == "arguments"), None)
        if args:
            alias = next((c for c in args.named_children if c.type == "alias"), None)
            if alias:
                return source_bytes[alias.start_byte:alias.end_byte].decode("utf-8")
        return None

    if form in ("def", "defp", "defmacro"):
        # Name is in arguments -> first call child's identifier, or bare identifier
        args = next((c for c in children if c.type == "arguments"), None)
        if args:
            for arg_child in args.named_children:
                if arg_child.type == "call":
                    # def hi(x) — the call node has identifier "hi"
                    ident = next(
                        (c for c in arg_child.named_children if c.type == "identifier"),
                        None,
                    )
                    if ident:
                        return source_bytes[ident.start_byte:ident.end_byte].decode("utf-8")
                if arg_child.type == "identifier":
                    return source_bytes[arg_child.start_byte:arg_child.end_byte].decode("utf-8")
        return None

    return None  # Not a definition form


def _extract_name_julia(node, source_bytes: bytes):
    """Julia: function_definition -> signature -> call_expression -> identifier.
    struct_definition -> type_head -> identifier.
    module_definition has a 'name' field."""
    if node.type == "function_definition":
        # signature -> call_expression -> first identifier
        sig = next((c for c in node.named_children if c.type == "signature"), None)
        if sig:
            call_expr = next(
                (c for c in sig.named_children if c.type == "call_expression"),
                None,
            )
            if call_expr:
                ident = next(
                    (c for c in call_expr.named_children if c.type == "identifier"),
                    None,
                )
                if ident:
                    return source_bytes[ident.start_byte:ident.end_byte].decode("utf-8")
        return None

    if node.type == "struct_definition":
        # type_head -> identifier
        head = next((c for c in node.named_children if c.type == "type_head"), None)
        if head:
            ident = next(
                (c for c in head.named_children if c.type == "identifier"),
                None,
            )
            if ident:
                return source_bytes[ident.start_byte:ident.end_byte].decode("utf-8")
        return None

    if node.type == "module_definition":
        name_node = node.child_by_field_name("name")
        if name_node:
            return source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8")
        return None

    return None  # Not handled — fall through to default


def _extract_name_clojure(node, source_bytes: bytes):
    """Clojure: list_lit where first sym_lit is a def-form.
    Returns the second sym_lit text as the name."""
    if node.type != "list_lit":
        return None

    sym_children = [c for c in node.named_children if c.type == "sym_lit"]
    if len(sym_children) < 2:
        return None

    first_text = source_bytes[sym_children[0].start_byte:sym_children[0].end_byte].decode("utf-8")
    # Only extract actual definition forms — skip ns (namespace) and non-def forms
    _DEF_FORMS = {"def", "defn", "defmacro", "defmethod", "defmulti", "defprotocol", "defonce"}
    if first_text not in _DEF_FORMS:
        return None

    return source_bytes[sym_children[1].start_byte:sym_children[1].end_byte].decode("utf-8")


def _extract_name_nim(node, source_bytes: bytes):
    """Nim: type_declaration has type_symbol_declaration child with 'name' field."""
    if node.type == "type_declaration":
        for child in node.children:
            if child.type == "type_symbol_declaration":
                name_node = child.child_by_field_name("name")
                if name_node:
                    return source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8")
        return None

    return None  # Not handled — fall through to default


def _resolve_kind_haskell(node, source_bytes: bytes, default_kind: str) -> str | None:
    """Haskell: skip 'function' nodes inside 'signature' (type annotations like foo :: Int -> Int)."""
    if node.type == "function" and node.parent and node.parent.type == "signature":
        return None  # Type expression, not a function definition — skip
    return default_kind


def _extract_name_erlang(node, source_bytes: bytes):
    """Erlang: fun_decl has no name field — name is in first function_clause child's 'name' field."""
    if node.type == "fun_decl":
        for child in node.children:
            if child.type == "function_clause":
                name_node = child.child_by_field_name("name")
                if name_node:
                    return source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8")
        return None

    return None  # Not handled — fall through to default


def _extract_name_zig(node, source_bytes: bytes):
    """Zig: Decl wraps FnProto/VarDecl — name is the first IDENTIFIER grandchild."""
    if node.type != "Decl":
        return None

    for child in node.named_children:
        if child.type in ("FnProto", "VarDecl"):
            for gc in child.named_children:
                if gc.type == "IDENTIFIER":
                    return source_bytes[gc.start_byte:gc.end_byte].decode("utf-8")
            return None
    return None


def _has_container_decl(node) -> bool:
    """Check if a Zig node contains a ContainerDecl (struct/enum/union) in its RHS."""
    for child in node.named_children:
        if child.type == "ContainerDecl":
            return True
        if _has_container_decl(child):
            return True
    return False


def _resolve_kind_zig(node, source_bytes: bytes, default_kind: str) -> str | None:
    """Zig: FnProto → function, VarDecl with ContainerDecl RHS → class, else constant."""
    if node.type != "Decl":
        return default_kind

    for child in node.named_children:
        if child.type == "FnProto":
            return "function"
        if child.type == "VarDecl":
            # Check AST for ContainerDecl (struct/enum/union) — not substring
            if _has_container_decl(child):
                return "class"
            return "constant"
    return default_kind


def _extract_name_d(node, source_bytes: bytes):
    """D: function/class/struct/interface/enum declarations — name is in identifier child."""
    if node.type in (
        "function_declaration", "class_declaration", "struct_declaration",
        "interface_declaration", "enum_declaration",
    ):
        for child in node.named_children:
            if child.type == "identifier":
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8")
        return None

    return None  # Not handled — fall through to default


def _extract_name_objc(node, source_bytes: bytes):
    """Objective-C: class_interface/class_implementation — first identifier child.
    method_declaration/method_definition — build selector from identifier + method_parameter parts."""
    if node.type in ("class_interface", "class_implementation"):
        for child in node.named_children:
            if child.type == "identifier":
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8")
        return None

    if node.type in ("method_declaration", "method_definition"):
        # Build full Objective-C selector name
        # Pattern: identifier (method_parameter identifier method_parameter ...)*
        # Selector: setValue:other:
        parts = []
        for child in node.children:
            if child.type == "identifier" and child.is_named:
                parts.append(source_bytes[child.start_byte:child.end_byte].decode("utf-8"))
            elif child.type == "method_parameter":
                # Each method_parameter means the preceding identifier is a selector part with colon
                if parts:
                    parts[-1] += ":"
        if parts:
            return "".join(parts)
        return None

    return None  # Not handled — fall through to default


def _extract_name_ocaml(node, source_bytes: bytes):
    """OCaml: value_definition → let_binding → value_name (pattern field).
    module_definition → module_binding → module_name child.
    type_definition → type_binding → type_constructor (name field)."""
    if node.type == "value_definition":
        for child in node.named_children:
            if child.type == "let_binding":
                # value_name is accessed via the pattern field
                pattern = child.child_by_field_name("pattern")
                if pattern and pattern.type == "value_name":
                    return source_bytes[pattern.start_byte:pattern.end_byte].decode("utf-8")
                # Fallback: first value_name child
                for gc in child.named_children:
                    if gc.type == "value_name":
                        return source_bytes[gc.start_byte:gc.end_byte].decode("utf-8")
        return None

    if node.type == "module_definition":
        for child in node.named_children:
            if child.type == "module_binding":
                for gc in child.named_children:
                    if gc.type == "module_name":
                        return source_bytes[gc.start_byte:gc.end_byte].decode("utf-8")
        return None

    if node.type == "type_definition":
        for child in node.named_children:
            if child.type == "type_binding":
                name_node = child.child_by_field_name("name")
                if name_node and name_node.type == "type_constructor":
                    return source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8")
                # Fallback: first type_constructor child
                for gc in child.named_children:
                    if gc.type == "type_constructor":
                        return source_bytes[gc.start_byte:gc.end_byte].decode("utf-8")
        return None

    return None  # Not handled — fall through to default


def _extract_name_fsharp(node, source_bytes: bytes):
    """F#: declaration_expression → function_or_value_defn → function_declaration_left/value_declaration_left → identifier.
    module_defn → identifier child.
    type_definition → record_type_defn/other → type_name → identifier."""
    if node.type == "declaration_expression":
        for child in node.named_children:
            if child.type == "function_or_value_defn":
                for gc in child.named_children:
                    if gc.type == "function_declaration_left":
                        for ggc in gc.named_children:
                            if ggc.type == "identifier":
                                return source_bytes[ggc.start_byte:ggc.end_byte].decode("utf-8")
                        return None
                    if gc.type == "value_declaration_left":
                        for ggc in gc.named_children:
                            if ggc.type in ("identifier", "identifier_pattern"):
                                return source_bytes[ggc.start_byte:ggc.end_byte].decode("utf-8")
                        return None
        return None

    if node.type == "module_defn":
        for child in node.named_children:
            if child.type == "identifier":
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8")
        return None

    if node.type == "type_definition":
        for child in node.named_children:
            # Various type defn forms: record_type_defn, union_type_defn, etc.
            for gc in child.named_children if hasattr(child, "named_children") else []:
                if gc.type == "type_name":
                    for ggc in gc.named_children:
                        if ggc.type == "identifier":
                            return source_bytes[ggc.start_byte:ggc.end_byte].decode("utf-8")
        return None

    return None  # Not handled — fall through to default


def _resolve_kind_fsharp(node, source_bytes: bytes, default_kind: str) -> str | None:
    """F#: module_defn → class, type_definition → type."""
    if node.type == "module_defn":
        return "class"
    return default_kind


def _extract_name_elm(node, source_bytes: bytes):
    """Elm: value_declaration → function_declaration_left → lower_case_identifier child.
    type_declaration and type_alias_declaration use name field (handled by default logic)."""
    if node.type == "value_declaration":
        for child in node.named_children:
            if child.type == "function_declaration_left":
                for gc in child.named_children:
                    if gc.type == "lower_case_identifier":
                        return source_bytes[gc.start_byte:gc.end_byte].decode("utf-8")
                return None
        return None

    return None  # Not handled — fall through to default


# ---------------------------------------------------------------------------
# Per-language call target extraction functions
# Each takes (node, spec, source_bytes, calls) and returns True if handled.
# ---------------------------------------------------------------------------

def _extract_call_java(node, spec, source_bytes: bytes, calls: list) -> bool:
    """Java method_invocation: name field is the method identifier."""
    if node.type == "method_invocation":
        name_node = node.child_by_field_name("name")
        if name_node:
            calls.append(source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8"))
        return True
    return False


def _extract_call_rust(node, spec, source_bytes: bytes, calls: list) -> bool:
    """Rust macro_invocation: extract macro name."""
    if node.type == "macro_invocation":
        macro_node = node.child_by_field_name("macro")
        if macro_node:
            calls.append(source_bytes[macro_node.start_byte:macro_node.end_byte].decode("utf-8"))
        return True
    return False


def _extract_call_php(node, spec, source_bytes: bytes, calls: list) -> bool:
    """PHP: member_call_expression and function_call_expression."""
    if node.type == "member_call_expression":
        name_node = node.child_by_field_name("name")
        if name_node:
            calls.append(source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8"))
        return True
    if node.type == "function_call_expression":
        func_node = node.child_by_field_name("function")
        if func_node:
            # PHP function node may be type "name" (simple calls like bar())
            # or a qualified_name / member_access. Try _extract_callee_name first,
            # fall back to raw text for "name" nodes.
            from .extractor import _extract_callee_name
            name = _extract_callee_name(func_node, source_bytes)
            if name is None and func_node.type == "name":
                name = source_bytes[func_node.start_byte:func_node.end_byte].decode("utf-8")
            if name:
                calls.append(name)
        return True
    return False


def _extract_call_csharp(node, spec, source_bytes: bytes, calls: list) -> bool:
    """C# invocation_expression: func() or obj.Method()."""
    if node.type == "invocation_expression":
        from .extractor import _extract_callee_name
        func_node = node.child_by_field_name("function")
        if func_node:
            name = _extract_callee_name(func_node, source_bytes)
            if name:
                calls.append(name)
        else:
            for child in node.named_children:
                name = _extract_callee_name(child, source_bytes)
                if name:
                    calls.append(name)
                    break
        return True
    return False


def _extract_call_perl(node, spec, source_bytes: bytes, calls: list) -> bool:
    """Perl method_call_expression: $self->bark()."""
    if node.type == "method_call_expression":
        method_node = node.child_by_field_name("method")
        if method_node is None:
            for child in node.children:
                if child.type in ("method", "bareword", "identifier"):
                    method_node = child
                    break
        if method_node:
            calls.append(source_bytes[method_node.start_byte:method_node.end_byte].decode("utf-8"))
        return True
    return False


def _extract_call_ruby(node, spec, source_bytes: bytes, calls: list) -> bool:
    """Ruby call: obj.method(args)."""
    if node.type == "call" and "call" in spec.call_node_types:
        method_node = node.child_by_field_name("method")
        if method_node:
            calls.append(source_bytes[method_node.start_byte:method_node.end_byte].decode("utf-8"))
        return True
    return False


def _extract_call_d(node, spec, source_bytes: bytes, calls: list) -> bool:
    """D call_expression: writeln("x") or foo.bar(1)."""
    if node.type == "call_expression":
        first = node.named_children[0] if node.named_children else None
        if first:
            if first.type == "identifier":
                calls.append(source_bytes[first.start_byte:first.end_byte].decode("utf-8"))
            elif first.type == "type":
                # Qualified calls like foo.bar(1) — the callee is a "type" node
                text = source_bytes[first.start_byte:first.end_byte].decode("utf-8")
                calls.append(text)
            else:
                text = source_bytes[first.start_byte:first.end_byte].decode("utf-8")
                if text:
                    calls.append(text)
        return True
    return False


def _extract_call_objc(node, spec, source_bytes: bytes, calls: list) -> bool:
    """ObjC message_expression: [obj doThing:1 with:2] → 'doThing:with:'."""
    if node.type == "message_expression":
        method_parts = node.children_by_field_name("method")
        if method_parts:
            names = [
                source_bytes[m.start_byte:m.end_byte].decode("utf-8")
                for m in method_parts
            ]
            if len(names) > 1:
                # Multi-part selector: join with ":" and append trailing ":"
                calls.append(":".join(names) + ":")
            elif len(names) == 1:
                # Check if this single-method call has a colon (takes arguments)
                has_colon = any(
                    c.type == ":" or (
                        not c.is_named
                        and source_bytes[c.start_byte:c.end_byte].decode("utf-8") == ":"
                    )
                    for c in node.children
                )
                if has_colon:
                    calls.append(names[0] + ":")
                else:
                    calls.append(names[0])
        return True
    return False


def _make_call_extractor(handlers: dict[str, Callable]) -> Callable:
    """Create a single extract_call_target function that dispatches by node type."""
    def _extract(node, spec, source_bytes: bytes, calls: list) -> bool:
        handler = handlers.get(node.type)
        if handler:
            return handler(node, spec, source_bytes, calls)
        return False
    return _extract


# File extension to language mapping
LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".php": "php",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".cs": "c_sharp",
    ".rb": "ruby",
    ".swift": "swift",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".dart": "dart",
    ".pl": "perl",
    ".pm": "perl",
    ".lua": "lua",
    ".sh": "bash",
    ".bash": "bash",
    ".scala": "scala",
    ".r": "r",
    ".R": "r",
    ".ex": "elixir",
    ".exs": "elixir",
    ".jl": "julia",
    ".clj": "clojure",
    ".cljc": "clojure",
    ".cljs": "clojure",
    ".nim": "nim",
    ".nims": "nim",
    ".hs": "haskell",
    ".erl": "erlang",
    ".hrl": "erlang",
    ".zig": "zig",
    ".d": "d",
    ".mm": "objc",
    ".ml": "ocaml",
    ".mli": "ocaml",
    ".fs": "fsharp",
    ".fsi": "fsharp",
    ".fsx": "fsharp",
    ".elm": "elm",
    ".sql": "sql",
    ".ps1": "powershell",
    ".psm1": "powershell",
    ".sol": "solidity",
    ".tf": "hcl",
    ".tfvars": "hcl",
    ".proto": "proto",
    ".graphql": "graphql",
    ".gql": "graphql",
    ".css": "css",
    ".scss": "scss",
    ".html": "html",
    ".htm": "html",
    ".xml": "xml",
    ".xsl": "xml",
    ".xsd": "xml",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".mk": "make",
    ".f90": "fortran",
    ".f95": "fortran",
    ".f03": "fortran",
    ".f08": "fortran",
    ".f": "fortran",
    ".cmake": "cmake",
    ".m": "matlab",
    ".cu": "cuda",
    ".cuh": "cuda",
    ".vv": "v",
    ".gleam": "gleam",
    ".odin": "odin",
    ".gd": "gdscript",
    ".sv": "verilog",
    ".vhd": "vhdl",
    ".vhdl": "vhdl",
    ".adb": "ada",
    ".ads": "ada",
    ".pas": "pascal",
    ".pp": "pascal",
    ".lisp": "commonlisp",
    ".cl": "commonlisp",
    ".lsp": "commonlisp",
    ".scm": "scheme",
    ".ss": "scheme",
    ".rkt": "racket",
    ".tcl": "tcl",
    ".dockerfile": "dockerfile",
    ".glsl": "glsl",
    ".vert": "glsl",
    ".frag": "glsl",
    ".geom": "glsl",
    ".comp": "glsl",
    ".hlsl": "hlsl",
    ".fx": "hlsl",
    ".wgsl": "wgsl",
    ".nix": "nix",
}


# Python specification
PYTHON_SPEC = LanguageSpec(
    ts_language="python",
    symbol_node_types={
        "function_definition": "function",
        "class_definition": "class",
    },
    name_fields={
        "function_definition": "name",
        "class_definition": "name",
    },
    param_fields={
        "function_definition": "parameters",
    },
    return_type_fields={
        "function_definition": "return_type",
    },
    docstring_strategy="next_sibling_string",
    decorator_node_type="decorator",
    container_node_types=["class_definition"],
    constant_patterns=["assignment"],
    type_patterns=["type_alias_statement"],
    call_node_types=["call"],
    import_node_types=["import_statement", "import_from_statement"],
    inheritance_fields=["argument_list"],
    extract_import=_make_import_dispatcher({
        "import_statement": _extract_import_python_import_statement,
        "import_from_statement": _extract_import_python_from,
    }),
    collect_type_names=_make_type_collector({
        "argument_list": _collect_types_argument_list,
    }),
)


# JavaScript specification
JAVASCRIPT_SPEC = LanguageSpec(
    ts_language="javascript",
    symbol_node_types={
        "function_declaration": "function",
        "class_declaration": "class",
        "method_definition": "method",
        "arrow_function": "function",
        "generator_function_declaration": "function",
    },
    name_fields={
        "function_declaration": "name",
        "class_declaration": "name",
        "method_definition": "name",
    },
    param_fields={
        "function_declaration": "parameters",
        "method_definition": "parameters",
        "arrow_function": "parameters",
    },
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=["class_declaration", "class"],
    constant_patterns=["lexical_declaration"],
    type_patterns=[],
    call_node_types=["call_expression"],
    import_node_types=["import_statement"],
    inheritance_fields=["class_heritage"],
    extract_import=_make_import_dispatcher({
        "import_statement": _extract_import_js_ts,
    }),
    collect_type_names=_make_type_collector({
        "class_heritage": _collect_types_class_heritage,
    }),
)


# TypeScript specification
TYPESCRIPT_SPEC = LanguageSpec(
    ts_language="typescript",
    symbol_node_types={
        "function_declaration": "function",
        "class_declaration": "class",
        "method_definition": "method",
        "arrow_function": "function",
        "interface_declaration": "type",
        "type_alias_declaration": "type",
        "enum_declaration": "type",
    },
    name_fields={
        "function_declaration": "name",
        "class_declaration": "name",
        "method_definition": "name",
        "interface_declaration": "name",
        "type_alias_declaration": "name",
        "enum_declaration": "name",
    },
    param_fields={
        "function_declaration": "parameters",
        "method_definition": "parameters",
        "arrow_function": "parameters",
    },
    return_type_fields={
        "function_declaration": "return_type",
        "method_definition": "return_type",
        "arrow_function": "return_type",
    },
    docstring_strategy="preceding_comment",
    decorator_node_type="decorator",
    container_node_types=["class_declaration", "class"],
    constant_patterns=["lexical_declaration"],
    type_patterns=["interface_declaration", "type_alias_declaration", "enum_declaration"],
    call_node_types=["call_expression"],
    import_node_types=["import_statement"],
    inheritance_fields=["class_heritage"],
    implementation_fields=["class_heritage"],
    extract_import=_make_import_dispatcher({
        "import_statement": _extract_import_js_ts,
    }),
    collect_type_names=_make_type_collector({
        "class_heritage": _collect_types_class_heritage,
    }),
)


# Go specification
GO_SPEC = LanguageSpec(
    ts_language="go",
    symbol_node_types={
        "function_declaration": "function",
        "method_declaration": "method",
        "type_declaration": "type",
    },
    name_fields={
        "function_declaration": "name",
        "method_declaration": "name",
        "type_declaration": "name",
    },
    param_fields={
        "function_declaration": "parameters",
        "method_declaration": "parameters",
    },
    return_type_fields={
        "function_declaration": "result",
        "method_declaration": "result",
    },
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=["const_declaration"],
    type_patterns=["type_declaration"],
    call_node_types=["call_expression"],
    import_node_types=["import_declaration"],
    extract_import=_make_import_dispatcher({
        "import_declaration": _extract_import_go,
    }),
)


# Rust specification
RUST_SPEC = LanguageSpec(
    ts_language="rust",
    symbol_node_types={
        "function_item": "function",
        "struct_item": "type",
        "enum_item": "type",
        "trait_item": "type",
        "impl_item": "class",
        "type_item": "type",
    },
    name_fields={
        "function_item": "name",
        "struct_item": "name",
        "enum_item": "name",
        "trait_item": "name",
        "type_item": "name",
    },
    param_fields={
        "function_item": "parameters",
    },
    return_type_fields={
        "function_item": "return_type",
    },
    docstring_strategy="preceding_comment",
    decorator_node_type="attribute_item",
    container_node_types=["impl_item", "trait_item"],
    constant_patterns=["const_item", "static_item"],
    type_patterns=["struct_item", "enum_item", "trait_item", "type_item"],
    call_node_types=["call_expression", "macro_invocation"],
    import_node_types=["use_declaration"],
    inheritance_fields=["trait_bounds"],
    extract_import=_make_import_dispatcher({
        "use_declaration": _extract_import_rust,
    }),
    collect_type_names=_make_type_collector({
        "trait_bounds": _collect_types_named_children,
    }),
    extract_call_target=_make_call_extractor({
        "macro_invocation": _extract_call_rust,
    }),
)


# Java specification
JAVA_SPEC = LanguageSpec(
    ts_language="java",
    symbol_node_types={
        "method_declaration": "method",
        "constructor_declaration": "method",
        "class_declaration": "class",
        "interface_declaration": "type",
        "enum_declaration": "type",
    },
    name_fields={
        "method_declaration": "name",
        "constructor_declaration": "name",
        "class_declaration": "name",
        "interface_declaration": "name",
        "enum_declaration": "name",
    },
    param_fields={
        "method_declaration": "parameters",
        "constructor_declaration": "parameters",
    },
    return_type_fields={
        "method_declaration": "type",
    },
    docstring_strategy="preceding_comment",
    decorator_node_type="marker_annotation",
    container_node_types=["class_declaration", "interface_declaration", "enum_declaration"],
    constant_patterns=["field_declaration"],
    type_patterns=["interface_declaration", "enum_declaration"],
    call_node_types=["method_invocation"],
    import_node_types=["import_declaration"],
    inheritance_fields=["superclass"],
    implementation_fields=["super_interfaces"],
    extract_import=_make_import_dispatcher({
        "import_declaration": _extract_import_java,
    }),
    collect_type_names=_make_type_collector({
        "superclass": _collect_types_superclass,
        "super_interfaces": _collect_types_super_interfaces,
        "interfaces": _collect_types_super_interfaces,
    }),
    extract_call_target=_make_call_extractor({
        "method_invocation": _extract_call_java,
    }),
)


# PHP specification
PHP_SPEC = LanguageSpec(
    ts_language="php",
    symbol_node_types={
        "function_definition": "function",
        "class_declaration": "class",
        "method_declaration": "method",
        "interface_declaration": "type",
        "trait_declaration": "type",
        "enum_declaration": "type",
    },
    name_fields={
        "function_definition": "name",
        "class_declaration": "name",
        "method_declaration": "name",
        "interface_declaration": "name",
        "trait_declaration": "name",
        "enum_declaration": "name",
    },
    param_fields={
        "function_definition": "parameters",
        "method_declaration": "parameters",
    },
    return_type_fields={
        "function_definition": "return_type",
        "method_declaration": "return_type",
    },
    docstring_strategy="preceding_comment",
    decorator_node_type="attribute",  # PHP 8 #[Attribute] syntax
    container_node_types=["class_declaration", "trait_declaration", "interface_declaration"],
    constant_patterns=["const_declaration"],
    type_patterns=["interface_declaration", "trait_declaration", "enum_declaration"],
    call_node_types=["function_call_expression", "member_call_expression"],
    import_node_types=["namespace_use_declaration"],
    inheritance_fields=["base_clause"],
    implementation_fields=["class_interface_clause"],
    extract_import=_make_import_dispatcher({
        "namespace_use_declaration": _extract_import_php,
    }),
    collect_type_names=_make_type_collector({
        "base_clause": _collect_types_named_children,
        "class_interface_clause": _collect_types_named_children,
    }),
    extract_call_target=_make_call_extractor({
        "member_call_expression": _extract_call_php,
        "function_call_expression": _extract_call_php,
    }),
)


# C specification
C_SPEC = LanguageSpec(
    ts_language="c",
    symbol_node_types={
        "function_definition": "function",
        "struct_specifier": "type",
        "enum_specifier": "type",
        "type_definition": "type",
    },
    name_fields={
        "struct_specifier": "name",
        "enum_specifier": "name",
        # function_definition and type_definition use declarator — handled in extractor
    },
    param_fields={},  # parameters are inside function_declarator — handled in extractor
    return_type_fields={
        "function_definition": "type",
    },
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=["struct_specifier"],
    constant_patterns=["preproc_def"],
    type_patterns=["type_definition", "struct_specifier", "enum_specifier"],
    call_node_types=["call_expression"],
    import_node_types=["preproc_include"],
    extract_import=_make_import_dispatcher({
        "preproc_include": _extract_import_c_include,
    }),
    extract_name=_extract_name_c_cpp,
)


# C++ specification
CPP_SPEC = LanguageSpec(
    ts_language="cpp",
    symbol_node_types={
        "function_definition": "function",
        "class_specifier": "class",
        "struct_specifier": "type",
        "enum_specifier": "type",
        "namespace_definition": "type",
    },
    name_fields={
        "class_specifier": "name",
        "struct_specifier": "name",
        "enum_specifier": "name",
        "namespace_definition": "name",
        # function_definition uses declarator — handled in extractor
    },
    param_fields={},  # parameters are inside function_declarator — handled in extractor
    return_type_fields={
        "function_definition": "type",
    },
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=["class_specifier", "struct_specifier", "namespace_definition"],
    constant_patterns=["preproc_def"],
    type_patterns=["class_specifier", "struct_specifier", "enum_specifier"],
    call_node_types=["call_expression"],
    import_node_types=["preproc_include", "using_declaration"],
    inheritance_fields=["base_class_clause"],
    extract_import=_make_import_dispatcher({
        "preproc_include": _extract_import_c_include,
        "using_declaration": _extract_import_cpp_using,
    }),
    collect_type_names=_make_type_collector({
        "base_class_clause": _collect_types_named_children,
    }),
    extract_name=_extract_name_c_cpp,
)


# C# specification
CSHARP_SPEC = LanguageSpec(
    ts_language="c_sharp",
    symbol_node_types={
        "method_declaration": "method",
        "constructor_declaration": "method",
        "class_declaration": "class",
        "struct_declaration": "type",
        "interface_declaration": "type",
        "enum_declaration": "type",
        "namespace_declaration": "type",
    },
    name_fields={
        "method_declaration": "name",
        "constructor_declaration": "name",
        "class_declaration": "name",
        "struct_declaration": "name",
        "interface_declaration": "name",
        "enum_declaration": "name",
        "namespace_declaration": "name",
    },
    param_fields={
        "method_declaration": "parameters",
        "constructor_declaration": "parameters",
    },
    return_type_fields={
        "method_declaration": "returns",
    },
    docstring_strategy="preceding_comment",
    decorator_node_type="attribute_list",
    container_node_types=["class_declaration", "struct_declaration", "interface_declaration", "namespace_declaration"],
    constant_patterns=["field_declaration"],
    type_patterns=["class_declaration", "struct_declaration", "interface_declaration", "enum_declaration"],
    call_node_types=["invocation_expression"],
    import_node_types=["using_directive"],
    inheritance_fields=["base_list"],
    implementation_fields=["base_list"],
    extract_import=_make_import_dispatcher({
        "using_directive": _extract_import_csharp_using,
    }),
    collect_type_names=_make_type_collector({
        "base_list": _collect_types_named_children,
    }),
    extract_call_target=_make_call_extractor({
        "invocation_expression": _extract_call_csharp,
    }),
)


# Ruby specification
RUBY_SPEC = LanguageSpec(
    ts_language="ruby",
    symbol_node_types={
        "method": "function",
        "singleton_method": "function",
        "class": "class",
        "module": "type",
    },
    name_fields={
        "method": "name",
        "singleton_method": "name",
        "class": "name",
        "module": "name",
    },
    param_fields={
        "method": "parameters",
        "singleton_method": "parameters",
    },
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=["class", "module"],
    constant_patterns=["assignment"],
    type_patterns=["class", "module"],
    call_node_types=["call"],
    import_node_types=[],  # Ruby uses require() calls — not a distinct node type
    inheritance_fields=["superclass"],
    collect_type_names=_make_type_collector({
        "superclass": _collect_types_superclass,
    }),
    extract_call_target=_make_call_extractor({
        "call": _extract_call_ruby,
    }),
)


# Swift specification
SWIFT_SPEC = LanguageSpec(
    ts_language="swift",
    symbol_node_types={
        "function_declaration": "function",
        "class_declaration": "class",
        "protocol_declaration": "type",
    },
    name_fields={
        "function_declaration": "name",
        "class_declaration": "name",
        "protocol_declaration": "name",
    },
    param_fields={},  # Swift parameters are positional children — partial extraction via signature
    return_type_fields={},  # return type is after -> token, positional
    docstring_strategy="preceding_comment",
    decorator_node_type="attribute",
    container_node_types=["class_declaration", "protocol_declaration"],
    constant_patterns=["property_declaration"],
    type_patterns=["class_declaration", "protocol_declaration"],
    call_node_types=["call_expression"],
    import_node_types=["import_declaration"],
    inheritance_fields=["inheritance_specifier"],
    extract_import=_make_import_dispatcher({
        "import_declaration": _extract_import_swift,
    }),
    collect_type_names=_make_type_collector({
        "inheritance_specifier": _collect_types_named_children,
    }),
)


# Kotlin specification
KOTLIN_SPEC = LanguageSpec(
    ts_language="kotlin",
    symbol_node_types={
        "function_declaration": "function",
        "class_declaration": "class",
        "object_declaration": "type",
    },
    name_fields={
        "function_declaration": "name",
        "class_declaration": "name",
        "object_declaration": "name",
    },
    param_fields={},  # Kotlin parameters use function_value_parameters — partial extraction via signature
    return_type_fields={},  # return type is positional
    docstring_strategy="preceding_comment",
    decorator_node_type="annotation",
    container_node_types=["class_declaration", "object_declaration"],
    constant_patterns=["property_declaration"],
    type_patterns=["class_declaration", "object_declaration"],
    call_node_types=["call_expression"],
    import_node_types=["import_header"],
    inheritance_fields=["delegation_specifiers"],
    extract_import=_make_import_dispatcher({
        "import_header": _extract_import_kotlin,
    }),
    collect_type_names=_make_type_collector({
        "delegation_specifiers": _collect_types_delegation_specifiers,
    }),
)


# Dart specification
# NOTE: Dart AST splits functions into sibling function_signature + function_body
# nodes rather than a single wrapper. The extractor handles this via
# _find_dart_body_sibling() to extend byte ranges and extract calls.
DART_SPEC = LanguageSpec(
    ts_language="dart",
    symbol_node_types={
        "function_signature": "function",
        "method_signature": "method",
        "class_definition": "class",
        "enum_declaration": "type",
        "mixin_declaration": "type",
    },
    name_fields={
        "class_definition": "name",
        "enum_declaration": "name",
        "mixin_declaration": "name",
        # function_signature/method_signature use identifier child — handled in extractor
    },
    param_fields={},  # Dart params are inside formal_parameter_list child of function_signature
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type="annotation",
    container_node_types=["class_definition", "mixin_declaration"],
    constant_patterns=[],
    type_patterns=["enum_declaration", "mixin_declaration"],
    call_node_types=[],  # Dart uses identifier + selector siblings, not call_expression nodes
    import_node_types=["import_or_export"],
    inheritance_fields=["superclass", "interfaces"],
    implementation_fields=["interfaces"],
    extract_import=_make_import_dispatcher({
        "import_or_export": _extract_import_dart,
    }),
    collect_type_names=_make_type_collector({
        "superclass": _collect_types_superclass,
        "interfaces": _collect_types_named_children,
    }),
    extract_name=_extract_name_dart,
)


# Perl specification
PERL_SPEC = LanguageSpec(
    ts_language="perl",
    symbol_node_types={
        "subroutine_declaration_statement": "function",
        "package_statement": "type",
    },
    name_fields={
        # subroutine uses bareword child — handled in extractor
        # package_statement uses second package child — handled in extractor
    },
    param_fields={},  # Perl params are extracted from @_ in body, not AST
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=["package_statement"],
    constant_patterns=[],
    type_patterns=[],
    call_node_types=["function_call_expression", "method_call_expression"],
    import_node_types=["use_statement"],
    extract_import=_make_import_dispatcher({
        "use_statement": _extract_import_perl,
    }),
    extract_name=_extract_name_perl,
    extract_call_target=_make_call_extractor({
        "method_call_expression": _extract_call_perl,
    }),
)


# Lua specification
LUA_SPEC = LanguageSpec(
    ts_language="lua",
    symbol_node_types={
        "function_declaration": "function",
    },
    name_fields={
        "function_declaration": "name",
    },
    param_fields={
        "function_declaration": "parameters",
    },
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=["variable_declaration"],
    type_patterns=[],
    call_node_types=["function_call"],
    import_node_types=[],  # Lua uses require() calls — not a distinct node type
)


# Bash specification
BASH_SPEC = LanguageSpec(
    ts_language="bash",
    symbol_node_types={
        "function_definition": "function",
    },
    name_fields={
        "function_definition": "name",
    },
    param_fields={},  # Bash functions have no parameter syntax in the AST
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=["variable_assignment", "declaration_command"],
    type_patterns=[],
    call_node_types=["command"],
    import_node_types=[],  # Bash uses source/. commands — not a distinct node type
)


# Scala specification
SCALA_SPEC = LanguageSpec(
    ts_language="scala",
    symbol_node_types={
        "function_definition": "function",
        "class_definition": "class",
        "object_definition": "class",
        "trait_definition": "type",
        "type_definition": "type",
    },
    name_fields={
        "function_definition": "name",
        "class_definition": "name",
        "object_definition": "name",
        "trait_definition": "name",
        "type_definition": "name",
    },
    param_fields={
        "function_definition": "parameters",
    },
    return_type_fields={
        "function_definition": "return_type",
    },
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=["class_definition", "object_definition", "trait_definition", "template_body"],
    constant_patterns=["val_definition"],
    type_patterns=["type_definition", "trait_definition"],
    call_node_types=["call_expression"],
    import_node_types=["import_declaration"],
    inheritance_fields=["extends_clause"],
)


# R specification
R_SPEC = LanguageSpec(
    ts_language="r",
    symbol_node_types={
        "binary_operator": "function",  # Determined dynamically by extract_name; RHS checked below
    },
    name_fields={
        # binary_operator uses custom extractor — no standard name field
    },
    param_fields={},  # R params are inside function_definition child, not directly accessible
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],  # Non-function assignments also use binary_operator — filtered by kind
    type_patterns=[],
    call_node_types=["call"],
    import_node_types=[],  # R uses library()/require() calls — not a distinct node type
    extract_name=_extract_name_r,
)


# Elixir specification
ELIXIR_SPEC = LanguageSpec(
    ts_language="elixir",
    symbol_node_types={
        "call": "function",  # defmodule/def/defp/defmacro are all call nodes
    },
    name_fields={
        # call nodes use custom extractor — no standard name field
    },
    param_fields={},  # Elixir params are inside nested call arguments
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=["call"],  # defmodule contains nested def calls
    constant_patterns=[],
    type_patterns=[],
    call_node_types=[],  # Elixir function calls are also call nodes — skip to avoid noise
    import_node_types=[],  # Elixir uses use/import/alias calls — not distinct node types
    extract_name=_extract_name_elixir,
    resolve_kind=_resolve_kind_elixir,
)


# Julia specification
JULIA_SPEC = LanguageSpec(
    ts_language="julia",
    symbol_node_types={
        "function_definition": "function",
        "struct_definition": "class",
        "module_definition": "class",
    },
    name_fields={
        # All use custom extractor or 'name' field (module_definition)
        "module_definition": "name",
    },
    param_fields={},  # Julia params are inside signature -> call_expression -> argument_list
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=["module_definition", "struct_definition"],
    constant_patterns=[],
    type_patterns=["struct_definition"],
    call_node_types=["call_expression"],
    import_node_types=["import_statement", "using_statement"],
    extract_name=_extract_name_julia,
    extract_import=_make_import_dispatcher({
        "import_statement": _extract_import_julia,
        "using_statement": _extract_import_julia,
    }),
)


# Clojure specification
CLOJURE_SPEC = LanguageSpec(
    ts_language="clojure",
    symbol_node_types={
        "list_lit": "function",  # def-forms are all list_lit nodes; kind determined by first sym
    },
    name_fields={
        # list_lit uses custom extractor — no standard name field
    },
    param_fields={},  # Clojure params are vec_lit children — not field-based
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=[],
    call_node_types=[],  # Clojure function calls are also list_lit — skip to avoid noise
    import_node_types=[],  # Clojure uses (require ...) / (import ...) — not distinct node types
    extract_name=_extract_name_clojure,
    resolve_kind=_resolve_kind_clojure,
)


# Nim specification
NIM_SPEC = LanguageSpec(
    ts_language="nim",
    symbol_node_types={
        "proc_declaration": "function",
        "func_declaration": "function",
        "type_declaration": "type",
    },
    name_fields={
        "proc_declaration": "name",
        "func_declaration": "name",
        # type_declaration uses custom extractor — no direct name field
    },
    param_fields={
        "proc_declaration": "parameters",
        "func_declaration": "parameters",
    },
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=["type_declaration"],
    call_node_types=["call"],
    import_node_types=["import_statement", "include_statement"],
    extract_name=_extract_name_nim,
    extract_import=_make_import_dispatcher({
        "import_statement": _extract_import_nim,
        "include_statement": _extract_import_nim,
    }),
)


# Haskell specification
HASKELL_SPEC = LanguageSpec(
    ts_language="haskell",
    symbol_node_types={
        "function": "function",
        "data_type": "class",
        "class": "class",
    },
    name_fields={
        "function": "name",
        "data_type": "name",
        "class": "name",
    },
    param_fields={},  # Haskell params are patterns — not field-based
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=["class"],
    constant_patterns=[],
    type_patterns=["data_type"],
    call_node_types=[],  # Haskell function application has no distinct call node type
    import_node_types=["imports"],
    resolve_kind=_resolve_kind_haskell,
    extract_import=_make_import_dispatcher({
        "imports": _extract_import_haskell,
    }),
)


# Erlang specification
ERLANG_SPEC = LanguageSpec(
    ts_language="erlang",
    symbol_node_types={
        "fun_decl": "function",
        "module_attribute": "class",
        "record_decl": "type",
    },
    name_fields={
        "module_attribute": "name",
        "record_decl": "name",
        # fun_decl uses custom extractor — name is in function_clause child
    },
    param_fields={},  # Erlang params are inside function_clause expr_args
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=["record_decl"],
    call_node_types=["call"],
    import_node_types=[],  # Erlang uses -import() attributes — not a distinct node type
    extract_name=_extract_name_erlang,
)


# Zig specification
ZIG_SPEC = LanguageSpec(
    ts_language="zig",
    symbol_node_types={
        "Decl": "function",  # Kind determined dynamically by resolve_kind
    },
    name_fields={
        # Decl uses custom extractor — no standard name field
    },
    param_fields={},  # Zig params are inside FnProto -> ParamDeclList
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=[],
    call_node_types=[],  # Zig function calls are complex — skip for now
    import_node_types=[],  # Zig uses @import() builtins — not a distinct node type
    extract_name=_extract_name_zig,
    resolve_kind=_resolve_kind_zig,
)


# D specification
D_SPEC = LanguageSpec(
    ts_language="d",
    symbol_node_types={
        "function_declaration": "function",
        "class_declaration": "class",
        "struct_declaration": "type",
        "interface_declaration": "type",
        "enum_declaration": "type",
    },
    name_fields={
        # All use custom extractor — identifier child, no name field
    },
    param_fields={
        "function_declaration": "parameters",
    },
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=["class_declaration", "struct_declaration", "interface_declaration"],
    constant_patterns=[],
    type_patterns=["struct_declaration", "interface_declaration", "enum_declaration"],
    call_node_types=["call_expression"],
    import_node_types=["import_declaration"],
    extract_name=_extract_name_d,
    extract_import=_make_import_dispatcher({
        "import_declaration": _extract_import_d,
    }),
    extract_call_target=_make_call_extractor({
        "call_expression": _extract_call_d,
    }),
)


# Objective-C specification
# NOTE: Only .mm is mapped (not .m, which collides with MATLAB).
# Index class_interface only for class symbols; class_implementation is excluded
# to avoid duplicate class entries. Both method_declaration (in @interface) and
# method_definition (in @implementation) are indexed.
OBJC_SPEC = LanguageSpec(
    ts_language="objc",
    symbol_node_types={
        "class_interface": "class",
        "class_implementation": "class",  # Needed so methods get parent context
        "method_declaration": "method",
        "method_definition": "method",
    },
    name_fields={
        # All use custom extractor — no standard name fields
    },
    param_fields={},  # ObjC params are method_parameter children
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=["class_interface", "class_implementation", "implementation_definition"],
    constant_patterns=[],
    type_patterns=[],
    call_node_types=["message_expression"],
    import_node_types=["preproc_include"],
    extract_name=_extract_name_objc,
    extract_import=_make_import_dispatcher({
        "preproc_include": _extract_import_c_include,
    }),
    extract_call_target=_make_call_extractor({
        "message_expression": _extract_call_objc,
    }),
)


# OCaml specification
OCAML_SPEC = LanguageSpec(
    ts_language="ocaml",
    symbol_node_types={
        "value_definition": "function",
        "module_definition": "class",
        "type_definition": "type",
    },
    name_fields={
        # All use custom extractor — names are in nested binding nodes
    },
    param_fields={},  # OCaml params are pattern children of let_binding
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=["module_definition"],
    constant_patterns=[],
    type_patterns=["type_definition"],
    call_node_types=[],  # OCaml function application has no distinct call node
    import_node_types=["open_module"],
    extract_name=_extract_name_ocaml,
    extract_import=_make_import_dispatcher({
        "open_module": _extract_import_ocaml,
    }),
)


# F# specification
FSHARP_SPEC = LanguageSpec(
    ts_language="fsharp",
    symbol_node_types={
        "declaration_expression": "function",
        "module_defn": "class",  # Kind set by resolve_kind
        "type_definition": "type",
    },
    name_fields={
        # All use custom extractor — names are in nested declaration nodes
    },
    param_fields={},  # F# params are in argument_patterns child
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=["module_defn"],
    constant_patterns=[],
    type_patterns=["type_definition"],
    call_node_types=[],  # F# function application — skip for now
    import_node_types=["import_decl"],
    extract_name=_extract_name_fsharp,
    resolve_kind=_resolve_kind_fsharp,
    extract_import=_make_import_dispatcher({
        "import_decl": _extract_import_fsharp,
    }),
)


# Elm specification
ELM_SPEC = LanguageSpec(
    ts_language="elm",
    symbol_node_types={
        "value_declaration": "function",
        "type_declaration": "type",
        "type_alias_declaration": "type",
    },
    name_fields={
        "type_declaration": "name",
        "type_alias_declaration": "name",
        # value_declaration uses custom extractor
    },
    param_fields={},  # Elm params are in function_declaration_left
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=["type_declaration", "type_alias_declaration"],
    call_node_types=[],  # Elm function application — no distinct call node
    import_node_types=["import_clause"],
    extract_name=_extract_name_elm,
    extract_import=_make_import_dispatcher({
        "import_clause": _extract_import_elm,
    }),
)


def _extract_name_sql(node, source_bytes: bytes):
    """SQL: extract name from CREATE TABLE/FUNCTION/VIEW/INDEX statements.
    For table/function/view: find object_reference child, join identifier children with '.'.
    For index: find first direct identifier child."""
    if node.type in ("create_table", "create_function", "create_view"):
        for child in node.named_children:
            if child.type == "object_reference":
                identifiers = [
                    source_bytes[c.start_byte:c.end_byte].decode("utf-8")
                    for c in child.named_children
                    if c.type == "identifier"
                ]
                if identifiers:
                    return ".".join(identifiers)
        return None

    if node.type == "create_index":
        for child in node.named_children:
            if child.type == "identifier":
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8")
        return None

    return None  # Not handled — fall through to default


def _extract_name_powershell(node, source_bytes: bytes):
    """PowerShell: extract name from function_statement, class_statement,
    and class_method_definition nodes."""
    if node.type == "function_statement":
        for child in node.named_children:
            if child.type == "function_name":
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8")
        return None

    if node.type in ("class_statement", "class_method_definition"):
        for child in node.named_children:
            if child.type == "simple_name":
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8")
        return None

    return None  # Not handled — fall through to default


def _extract_name_solidity(node, source_bytes: bytes):
    """Solidity: extract name from contract/interface/function/event/modifier declarations.
    All use first identifier child. Unnamed functions (constructor, fallback, receive)
    return None."""
    for child in node.named_children:
        if child.type == "identifier":
            return source_bytes[child.start_byte:child.end_byte].decode("utf-8")
    return None  # Unnamed (e.g., constructor) — skip


# SQL specification
SQL_SPEC = LanguageSpec(
    ts_language="sql",
    symbol_node_types={
        "create_table": "class",
        "create_function": "function",
        "create_view": "class",
        "create_index": "constant",
    },
    name_fields={},  # All use custom extraction
    param_fields={},
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_sql,
)


# PowerShell specification
POWERSHELL_SPEC = LanguageSpec(
    ts_language="powershell",
    symbol_node_types={
        "function_statement": "function",
        "class_statement": "class",
        "class_method_definition": "function",
    },
    name_fields={},  # All use custom extraction
    param_fields={},
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=["class_statement"],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_powershell,
)


# Solidity specification
SOLIDITY_SPEC = LanguageSpec(
    ts_language="solidity",
    symbol_node_types={
        "contract_declaration": "class",
        "interface_declaration": "class",
        "function_definition": "function",
        "event_definition": "function",
        "modifier_definition": "function",
    },
    name_fields={},  # All use custom extraction
    param_fields={},
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=["contract_declaration", "interface_declaration"],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_solidity,
)


# ---------------------------------------------------------------------------
# HCL custom extractors
# ---------------------------------------------------------------------------

def _extract_name_hcl(node, source_bytes: bytes):
    """HCL: block nodes use first identifier child as block type,
    then string_lit children (with template_literal inside) as labels.
    resource/data → 'type.name', variable/module/output → just name, others → skip."""
    if node.type != "block":
        return None

    # Find block type from first identifier child
    block_type = None
    for child in node.named_children:
        if child.type == "identifier":
            block_type = source_bytes[child.start_byte:child.end_byte].decode("utf-8")
            break

    if block_type is None:
        return None

    # Collect labels from string_lit children (extract template_literal text)
    labels = []
    for child in node.named_children:
        if child.type == "string_lit":
            for sub in child.named_children:
                if sub.type == "template_literal":
                    labels.append(
                        source_bytes[sub.start_byte:sub.end_byte].decode("utf-8")
                    )
                    break

    if not labels:
        return None  # locals, terraform blocks — skip

    if len(labels) >= 2:
        # resource "aws_instance" "web" → aws_instance.web
        return f"{labels[0]}.{labels[1]}"

    return labels[0]  # variable "region" → region


def _resolve_kind_hcl(node, source_bytes: bytes, default_kind: str) -> str | None:
    """HCL: map block type identifier to symbol kind."""
    if node.type != "block":
        return default_kind

    for child in node.named_children:
        if child.type == "identifier":
            block_type = source_bytes[child.start_byte:child.end_byte].decode("utf-8")
            kind_map = {
                "resource": "class",
                "data": "class",
                "variable": "constant",
                "output": "constant",
                "module": "function",
            }
            return kind_map.get(block_type)  # None for locals, terraform → skip
    return None


# HCL specification
HCL_SPEC = LanguageSpec(
    ts_language="hcl",
    symbol_node_types={"block": "class"},  # Default, overridden by resolve_kind
    name_fields={},
    param_fields={},
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_hcl,
    resolve_kind=_resolve_kind_hcl,
)


# ---------------------------------------------------------------------------
# Protobuf custom extractors
# ---------------------------------------------------------------------------

def _extract_name_proto(node, source_bytes: bytes):
    """Proto: message/service/enum/rpc have a name-wrapper child
    (message_name, service_name, etc.) containing an identifier."""
    wrapper_map = {
        "message": "message_name",
        "service": "service_name",
        "enum": "enum_name",
        "rpc": "rpc_name",
    }
    wrapper_type = wrapper_map.get(node.type)
    if wrapper_type is None:
        return None

    for child in node.named_children:
        if child.type == wrapper_type:
            for sub in child.named_children:
                if sub.type == "identifier":
                    return source_bytes[sub.start_byte:sub.end_byte].decode("utf-8")
            break
    return None


# Protobuf specification
PROTO_SPEC = LanguageSpec(
    ts_language="proto",
    symbol_node_types={
        "message": "class",
        "service": "class",
        "enum": "class",
        "rpc": "function",
    },
    name_fields={},
    param_fields={},
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=["message", "service"],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_proto,
)


# ---------------------------------------------------------------------------
# GraphQL custom extractors
# ---------------------------------------------------------------------------

def _extract_name_graphql(node, source_bytes: bytes):
    """GraphQL: type definitions have a 'name' child node (GraphQL name node)."""
    for child in node.named_children:
        if child.type == "name":
            return source_bytes[child.start_byte:child.end_byte].decode("utf-8")
    return None


# GraphQL specification
GRAPHQL_SPEC = LanguageSpec(
    ts_language="graphql",
    symbol_node_types={
        "object_type_definition": "class",
        "interface_type_definition": "class",
        "enum_type_definition": "class",
        "input_object_type_definition": "class",
    },
    name_fields={},
    param_fields={},
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_graphql,
)


# ---------------------------------------------------------------------------
# CSS custom extractors
# ---------------------------------------------------------------------------

def _extract_name_css(node, source_bytes: bytes):
    """CSS: rule_set → selectors child text; keyframes_statement → keyframes_name child text."""
    if node.type == "rule_set":
        for child in node.named_children:
            if child.type == "selectors":
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8").strip()
        return None

    if node.type == "keyframes_statement":
        for child in node.named_children:
            if child.type == "keyframes_name":
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8").strip()
        return None

    return None


CSS_SPEC = LanguageSpec(
    ts_language="css",
    symbol_node_types={
        "rule_set": "class",
        "keyframes_statement": "function",
    },
    name_fields={},
    param_fields={},
    return_type_fields={},
    docstring_strategy="",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_css,
)


# ---------------------------------------------------------------------------
# SCSS custom extractors
# ---------------------------------------------------------------------------

def _extract_name_scss(node, source_bytes: bytes):
    """SCSS: same as CSS, plus declaration → property_name child text."""
    if node.type == "rule_set":
        for child in node.named_children:
            if child.type == "selectors":
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8").strip()
        return None

    if node.type == "keyframes_statement":
        for child in node.named_children:
            if child.type == "keyframes_name":
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8").strip()
        return None

    if node.type == "declaration":
        for child in node.named_children:
            if child.type == "property_name":
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8").strip()
        return None

    return None


def _resolve_kind_scss(node, source_bytes: bytes, default_kind: str) -> str | None:
    """SCSS: for declarations, only extract $variable declarations (skip regular properties)."""
    if node.type == "declaration":
        for child in node.named_children:
            if child.type == "property_name":
                text = source_bytes[child.start_byte:child.end_byte].decode("utf-8").strip()
                if not text.startswith("$"):
                    return None  # Skip non-variable declarations
                return default_kind
        return None
    return default_kind


SCSS_SPEC = LanguageSpec(
    ts_language="scss",
    symbol_node_types={
        "rule_set": "class",
        "keyframes_statement": "function",
        "declaration": "constant",
    },
    name_fields={},
    param_fields={},
    return_type_fields={},
    docstring_strategy="",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_scss,
    resolve_kind=_resolve_kind_scss,
)


# ---------------------------------------------------------------------------
# HTML custom extractors
# ---------------------------------------------------------------------------

def _extract_name_html(node, source_bytes: bytes):
    """HTML: element → find start_tag child, then get tag_name child text."""
    if node.type == "element":
        for child in node.named_children:
            if child.type == "start_tag":
                for sub in child.named_children:
                    if sub.type == "tag_name":
                        return source_bytes[sub.start_byte:sub.end_byte].decode("utf-8")
                break
    return None


def _resolve_kind_html(node, source_bytes: bytes, default_kind: str) -> str | None:
    """HTML: only extract root elements (direct children of document)."""
    if node.type == "element":
        if node.parent is None or node.parent.type != "document":
            return None
    return default_kind


HTML_SPEC = LanguageSpec(
    ts_language="html",
    symbol_node_types={"element": "class"},
    name_fields={},
    param_fields={},
    return_type_fields={},
    docstring_strategy="",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_html,
    resolve_kind=_resolve_kind_html,
    signature_from_name=True,
)


# ---------------------------------------------------------------------------
# XML custom extractors
# ---------------------------------------------------------------------------

def _extract_name_xml(node, source_bytes: bytes):
    """XML: element → find STag or EmptyElemTag child, then get Name child text."""
    if node.type == "element":
        for child in node.named_children:
            if child.type in ("STag", "EmptyElemTag"):
                for sub in child.named_children:
                    if sub.type == "Name":
                        return source_bytes[sub.start_byte:sub.end_byte].decode("utf-8")
                break
    return None


def _resolve_kind_xml(node, source_bytes: bytes, default_kind: str) -> str | None:
    """XML: only extract root elements (direct children of document)."""
    if node.type == "element":
        if node.parent is None or node.parent.type != "document":
            return None
    return default_kind


XML_SPEC = LanguageSpec(
    ts_language="xml",
    symbol_node_types={"element": "class"},
    name_fields={},
    param_fields={},
    return_type_fields={},
    docstring_strategy="",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_xml,
    resolve_kind=_resolve_kind_xml,
    signature_from_name=True,
)


# ---------------------------------------------------------------------------
# YAML custom extractors
# ---------------------------------------------------------------------------

def _extract_name_yaml(node, source_bytes: bytes):
    """YAML: block_mapping_pair → get key from first flow_node child.

    Handles plain_scalar (unquoted), double_quote_scalar, and single_quote_scalar keys.
    """
    if node.type == "block_mapping_pair":
        for child in node.named_children:
            if child.type == "flow_node":
                for sub in child.named_children:
                    if sub.type == "plain_scalar":
                        return source_bytes[sub.start_byte:sub.end_byte].decode("utf-8").strip()
                    if sub.type in ("double_quote_scalar", "single_quote_scalar"):
                        raw = source_bytes[sub.start_byte:sub.end_byte].decode("utf-8").strip()
                        return _strip_quotes(raw)
                # flow_node might directly contain text
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8").strip()
        # Fallback: first named child could be the key directly
        if node.named_child_count > 0:
            first = node.named_children[0]
            if first.type == "flow_node":
                return source_bytes[first.start_byte:first.end_byte].decode("utf-8").strip()
    return None


def _resolve_kind_yaml(node, source_bytes: bytes, default_kind: str) -> str | None:
    """YAML: only extract top-level block_mapping_pair nodes.

    Valid path: block_mapping_pair → block_mapping → block_node → document.
    Walk up 3 parents and verify the chain. If deeper, return None.
    """
    if node.type != "block_mapping_pair":
        return default_kind

    parent = node.parent
    if parent is None or parent.type != "block_mapping":
        return None

    grandparent = parent.parent
    if grandparent is None or grandparent.type != "block_node":
        return None

    great_grandparent = grandparent.parent
    if great_grandparent is None:
        return None

    # Accept both 'document' and 'stream' as top-level — some YAML grammars
    # have stream → document → block_node → block_mapping → block_mapping_pair
    if great_grandparent.type in ("document", "stream"):
        return default_kind

    return None


YAML_SPEC = LanguageSpec(
    ts_language="yaml",
    symbol_node_types={"block_mapping_pair": "constant"},
    name_fields={},
    param_fields={},
    return_type_fields={},
    docstring_strategy="",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_yaml,
    resolve_kind=_resolve_kind_yaml,
    signature_from_name=True,
)


# ---------------------------------------------------------------------------
# JSON custom extractors
# ---------------------------------------------------------------------------

def _extract_name_json(node, source_bytes: bytes):
    """JSON: pair → get 'key' field (child_by_field_name), strip quotes."""
    if node.type == "pair":
        key_node = node.child_by_field_name("key")
        if key_node:
            text = source_bytes[key_node.start_byte:key_node.end_byte].decode("utf-8")
            return _strip_quotes(text)
    return None


def _resolve_kind_json(node, source_bytes: bytes, default_kind: str) -> str | None:
    """JSON: only extract top-level pairs (parent object is direct child of document)."""
    if node.type == "pair":
        parent = node.parent
        if parent is None or parent.type != "object":
            return None
        grandparent = parent.parent
        if grandparent is None or grandparent.type != "document":
            return None
        return default_kind
    return default_kind


JSON_SPEC = LanguageSpec(
    ts_language="json",
    symbol_node_types={"pair": "constant"},
    name_fields={},
    param_fields={},
    return_type_fields={},
    docstring_strategy="",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_json,
    resolve_kind=_resolve_kind_json,
    signature_from_name=True,
)


# ---------------------------------------------------------------------------
# TOML custom extractors
# ---------------------------------------------------------------------------

def _extract_name_toml(node, source_bytes: bytes):
    """TOML: table → bare_key child text; pair → first bare_key or quoted_key child text."""
    if node.type == "table":
        for child in node.named_children:
            if child.type == "bare_key":
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8")
        return None

    if node.type == "pair":
        for child in node.named_children:
            if child.type == "bare_key":
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8")
            if child.type == "quoted_key":
                raw = source_bytes[child.start_byte:child.end_byte].decode("utf-8")
                return _strip_quotes(raw)
        return None

    return None


def _resolve_kind_toml(node, source_bytes: bytes, default_kind: str) -> str | None:
    """TOML: for pair, only extract top-level (parent is document). For table, always keep."""
    if node.type == "pair":
        if node.parent is None or node.parent.type != "document":
            return None
        return default_kind
    return default_kind


TOML_SPEC = LanguageSpec(
    ts_language="toml",
    symbol_node_types={
        "table": "class",
        "pair": "constant",
    },
    name_fields={},
    param_fields={},
    return_type_fields={},
    docstring_strategy="",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_toml,
    resolve_kind=_resolve_kind_toml,
    signature_from_name=True,
)


# ---------------------------------------------------------------------------
# Make custom extractors
# ---------------------------------------------------------------------------

def _extract_name_make(node, source_bytes: bytes):
    """Make: rule → find targets named child, then get first named child text."""
    if node.type == "rule":
        targets = node.child_by_field_name("targets")
        if targets is None:
            # Fallback: find first child of a target-like type
            for child in node.named_children:
                if child.type in ("targets", "word"):
                    targets = child
                    break
        if targets is not None:
            # Get first named child (usually a 'word' node)
            if targets.named_child_count > 0:
                first = targets.named_children[0]
                return source_bytes[first.start_byte:first.end_byte].decode("utf-8").strip()
            # If no named children, use the targets node text directly
            return source_bytes[targets.start_byte:targets.end_byte].decode("utf-8").strip()
    return None


MAKE_SPEC = LanguageSpec(
    ts_language="make",
    symbol_node_types={"rule": "function"},
    name_fields={},
    param_fields={},
    return_type_fields={},
    docstring_strategy="",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_make,
)


# ---------------------------------------------------------------------------
# Fortran custom extractors
# ---------------------------------------------------------------------------

def _extract_name_fortran(node, source_bytes: bytes):
    """Fortran: subroutine/function → subroutine_statement/function_statement → name child.
    program → program_statement child → name child."""
    if node.type in ("subroutine", "function"):
        # Name is inside subroutine_statement or function_statement child
        stmt_types = ("subroutine_statement", "function_statement")
        for child in node.named_children:
            if child.type in stmt_types:
                for gc in child.named_children:
                    if gc.type in ("name", "identifier"):
                        return source_bytes[gc.start_byte:gc.end_byte].decode("utf-8")
                return None
        # Fallback: try child_by_field_name or direct identifier
        name_node = node.child_by_field_name("name")
        if name_node:
            return source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8")
        for child in node.named_children:
            if child.type in ("name", "identifier"):
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8")
        return None

    if node.type == "program":
        for child in node.named_children:
            if child.type == "program_statement":
                for gc in child.named_children:
                    if gc.type in ("name", "identifier"):
                        return source_bytes[gc.start_byte:gc.end_byte].decode("utf-8")
                return None
        return None

    return None


def _extract_import_fortran(node, source_bytes: bytes) -> list[str]:
    """Fortran: subroutine/function/program wrapper → find use_statement children → module_name."""
    imports = []
    for child in node.named_children:
        if child.type == "use_statement":
            mod = child.child_by_field_name("module_name")
            if mod is None:
                mod = _find_child_by_type(child, "module_name")
            if mod:
                imports.append(source_bytes[mod.start_byte:mod.end_byte].decode("utf-8"))
    return imports


def _extract_call_target_fortran(node, spec, source_bytes: bytes, calls: list) -> bool:
    """Fortran: subroutine_call → field 'subroutine' (identifier)."""
    if node.type == "subroutine_call":
        sub = node.child_by_field_name("subroutine")
        if sub is None:
            sub = _find_child_by_type(node, "identifier")
        if sub:
            calls.append(source_bytes[sub.start_byte:sub.end_byte].decode("utf-8"))
        return True
    return False


FORTRAN_SPEC = LanguageSpec(
    ts_language="fortran",
    symbol_node_types={
        "subroutine": "function",
        "function": "function",
        "program": "class",
    },
    name_fields={},
    param_fields={},
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=["program"],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_fortran,
    call_node_types=["subroutine_call"],
    import_node_types=["subroutine", "function", "program"],
    extract_import=_make_import_dispatcher({
        "subroutine": _extract_import_fortran,
        "function": _extract_import_fortran,
        "program": _extract_import_fortran,
    }),
    extract_call_target=_extract_call_target_fortran,
)


# ---------------------------------------------------------------------------
# CMake custom extractors
# ---------------------------------------------------------------------------

def _extract_name_cmake(node, source_bytes: bytes):
    """CMake: function_def → function_command → argument_list → first argument.
    macro_def → macro_command → argument_list → first argument."""
    if node.type == "function_def":
        for child in node.named_children:
            if child.type == "function_command":
                for gc in child.named_children:
                    if gc.type == "argument_list":
                        for arg in gc.named_children:
                            if arg.type == "argument":
                                raw = source_bytes[arg.start_byte:arg.end_byte].decode("utf-8")
                                return _strip_quotes(raw)
                        # Fallback: first named child of argument_list
                        if gc.named_child_count > 0:
                            raw = source_bytes[gc.named_children[0].start_byte:gc.named_children[0].end_byte].decode("utf-8")
                            return _strip_quotes(raw)
                return None
        return None

    if node.type == "macro_def":
        for child in node.named_children:
            if child.type == "macro_command":
                for gc in child.named_children:
                    if gc.type == "argument_list":
                        for arg in gc.named_children:
                            if arg.type == "argument":
                                raw = source_bytes[arg.start_byte:arg.end_byte].decode("utf-8")
                                return _strip_quotes(raw)
                        if gc.named_child_count > 0:
                            raw = source_bytes[gc.named_children[0].start_byte:gc.named_children[0].end_byte].decode("utf-8")
                            return _strip_quotes(raw)
                return None
        return None

    return None


CMAKE_SPEC = LanguageSpec(
    ts_language="cmake",
    symbol_node_types={
        "function_def": "function",
        "macro_def": "function",
    },
    name_fields={},
    param_fields={},
    return_type_fields={},
    docstring_strategy="",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_cmake,
)


# ---------------------------------------------------------------------------
# MATLAB custom extractors
# ---------------------------------------------------------------------------

def _extract_name_matlab(node, source_bytes: bytes):
    """MATLAB: function_definition → identifier child directly."""
    if node.type == "function_definition":
        for child in node.named_children:
            if child.type == "identifier":
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8")
        return None

    return None


def _extract_call_target_matlab(node, spec, source_bytes: bytes, calls: list) -> bool:
    """MATLAB: function_call → 'name' field (NOT 'function' field)."""
    if node.type == "function_call":
        name_node = node.child_by_field_name("name")
        if name_node:
            calls.append(source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8"))
        return True
    return False


MATLAB_SPEC = LanguageSpec(
    ts_language="matlab",
    symbol_node_types={"function_definition": "function"},
    name_fields={},
    param_fields={},
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_matlab,
    call_node_types=["function_call"],
    extract_call_target=_extract_call_target_matlab,
)


# ---------------------------------------------------------------------------
# CUDA specification (C-like, reuses _extract_name_c_cpp)
# ---------------------------------------------------------------------------

CUDA_SPEC = LanguageSpec(
    ts_language="cuda",
    symbol_node_types={
        "function_definition": "function",
        "struct_specifier": "type",
    },
    name_fields={
        "struct_specifier": "name",
    },
    param_fields={},
    return_type_fields={
        "function_definition": "type",
    },
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=["struct_specifier"],
    constant_patterns=[],
    type_patterns=["struct_specifier"],
    extract_name=_extract_name_c_cpp,
    call_node_types=["call_expression"],
    import_node_types=["preproc_include"],
    extract_import=_make_import_dispatcher({
        "preproc_include": _extract_import_c_include,
    }),
)


# ---------------------------------------------------------------------------
# V language custom extractors
# ---------------------------------------------------------------------------

def _extract_name_v(node, source_bytes: bytes):
    """V: function_declaration → first identifier child.
    struct_declaration → first type_identifier child."""
    if node.type == "function_declaration":
        for child in node.named_children:
            if child.type == "identifier":
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8")
        return None

    if node.type == "struct_declaration":
        for child in node.named_children:
            if child.type == "type_identifier":
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8")
        return None

    return None


def _extract_import_v(node, source_bytes: bytes) -> list[str]:
    """V: import_declaration → field 'path' (import_path) → text."""
    path_node = node.child_by_field_name("path")
    if path_node:
        return [source_bytes[path_node.start_byte:path_node.end_byte].decode("utf-8")]
    # Fallback: first named child of type import_path
    for child in node.named_children:
        if child.type == "import_path":
            return [source_bytes[child.start_byte:child.end_byte].decode("utf-8")]
    return []


V_SPEC = LanguageSpec(
    ts_language="v",
    symbol_node_types={
        "function_declaration": "function",
        "struct_declaration": "class",
    },
    name_fields={},
    param_fields={},
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_v,
    call_node_types=["call_expression"],
    import_node_types=["import_declaration"],
    extract_import=_make_import_dispatcher({
        "import_declaration": _extract_import_v,
    }),
)


# ---------------------------------------------------------------------------
# Gleam custom extractors
# ---------------------------------------------------------------------------

def _extract_name_gleam(node, source_bytes: bytes):
    """Gleam: function → first identifier named child."""
    if node.type == "function":
        for child in node.named_children:
            if child.type == "identifier":
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8")
        return None

    return None


def _extract_import_gleam(node, source_bytes: bytes) -> list[str]:
    """Gleam: import → field 'module' → module node text."""
    mod = node.child_by_field_name("module")
    if mod:
        return [source_bytes[mod.start_byte:mod.end_byte].decode("utf-8")]
    return []


def _extract_call_target_gleam(node, spec, source_bytes: bytes, calls: list) -> bool:
    """Gleam: function_call → function field. If field_access, join record.field."""
    if node.type == "function_call":
        func = node.child_by_field_name("function")
        if func:
            if func.type == "field_access":
                record = func.child_by_field_name("record")
                field = func.child_by_field_name("field")
                if record and field:
                    rec_text = source_bytes[record.start_byte:record.end_byte].decode("utf-8")
                    field_text = source_bytes[field.start_byte:field.end_byte].decode("utf-8")
                    calls.append(f"{rec_text}.{field_text}")
                    return True
            # Simple identifier call
            text = source_bytes[func.start_byte:func.end_byte].decode("utf-8")
            if text:
                calls.append(text)
        return True
    return False


GLEAM_SPEC = LanguageSpec(
    ts_language="gleam",
    symbol_node_types={"function": "function"},
    name_fields={},
    param_fields={},
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_gleam,
    call_node_types=["function_call"],
    import_node_types=["import"],
    extract_import=_make_import_dispatcher({
        "import": _extract_import_gleam,
    }),
    extract_call_target=_extract_call_target_gleam,
)


# ---------------------------------------------------------------------------
# Odin custom extractors
# ---------------------------------------------------------------------------

def _extract_name_odin(node, source_bytes: bytes):
    """Odin: procedure_declaration → first identifier named child."""
    if node.type == "procedure_declaration":
        for child in node.named_children:
            if child.type == "identifier":
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8")
        return None

    return None


def _extract_import_odin(node, source_bytes: bytes) -> list[str]:
    """Odin: import_declaration → string child → string_content grandchild text."""
    for child in node.named_children:
        if child.type == "string":
            for gc in child.named_children:
                if gc.type == "string_content":
                    return [source_bytes[gc.start_byte:gc.end_byte].decode("utf-8")]
            # Fallback: strip quotes from string node itself
            text = source_bytes[child.start_byte:child.end_byte].decode("utf-8")
            return [text.strip('"')]
    return []


ODIN_SPEC = LanguageSpec(
    ts_language="odin",
    symbol_node_types={"procedure_declaration": "function"},
    name_fields={},
    param_fields={},
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_odin,
    call_node_types=["call_expression"],
    import_node_types=["import_declaration"],
    extract_import=_make_import_dispatcher({
        "import_declaration": _extract_import_odin,
    }),
)


# ---------------------------------------------------------------------------
# GDScript specification (name_fields work directly)
# ---------------------------------------------------------------------------

def _extract_call_target_gdscript(node, spec, source_bytes: bytes, calls: list) -> bool:
    """GDScript: call → first child is identifier (callee), no 'function' field."""
    if node.type == "call":
        for child in node.named_children:
            if child.type == "identifier":
                calls.append(source_bytes[child.start_byte:child.end_byte].decode("utf-8"))
                return True
        # Fallback: first child (even unnamed)
        if node.child_count > 0:
            first = node.children[0]
            if first.type == "identifier":
                calls.append(source_bytes[first.start_byte:first.end_byte].decode("utf-8"))
        return True
    return False


GDSCRIPT_SPEC = LanguageSpec(
    ts_language="gdscript",
    symbol_node_types={
        "function_definition": "function",
        "variable_statement": "constant",
    },
    name_fields={
        "function_definition": "name",
        "variable_statement": "name",
    },
    param_fields={},
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=[],
    call_node_types=["call"],
    extract_call_target=_extract_call_target_gdscript,
)


# ---------------------------------------------------------------------------
# Verilog custom extractors
# ---------------------------------------------------------------------------

def _extract_name_verilog(node, source_bytes: bytes):
    """Verilog: module_declaration → module_header child → simple_identifier child text."""
    if node.type == "module_declaration":
        for child in node.named_children:
            if child.type == "module_header":
                for gc in child.named_children:
                    if gc.type == "simple_identifier":
                        return source_bytes[gc.start_byte:gc.end_byte].decode("utf-8")
                return None
        # Fallback: look for simple_identifier directly
        for child in node.named_children:
            if child.type == "simple_identifier":
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8")
        return None

    return None


VERILOG_SPEC = LanguageSpec(
    ts_language="verilog",
    symbol_node_types={"module_declaration": "class"},
    name_fields={},
    param_fields={},
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_verilog,
)


# ---------------------------------------------------------------------------
# VHDL custom extractors
# ---------------------------------------------------------------------------

def _extract_name_vhdl(node, source_bytes: bytes):
    """VHDL: entity_declaration/architecture_body → first identifier named child."""
    if node.type in ("entity_declaration", "architecture_body"):
        for child in node.named_children:
            if child.type == "identifier":
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8")
        return None

    return None


VHDL_SPEC = LanguageSpec(
    ts_language="vhdl",
    symbol_node_types={
        "entity_declaration": "class",
        "architecture_body": "class",
    },
    name_fields={},
    param_fields={},
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_vhdl,
)


# ---------------------------------------------------------------------------
# Ada custom extractors
# ---------------------------------------------------------------------------

def _extract_name_ada(node, source_bytes: bytes):
    """Ada: subprogram_body → find procedure_specification or function_specification child
    → get first identifier child from it (NOT from subprogram_body directly, which has a
    trailing end-name identifier)."""
    if node.type == "subprogram_body":
        for child in node.named_children:
            if child.type in ("procedure_specification", "function_specification"):
                for gc in child.named_children:
                    if gc.type == "identifier":
                        return source_bytes[gc.start_byte:gc.end_byte].decode("utf-8")
                return None
        return None

    return None


def _extract_import_ada(node, source_bytes: bytes) -> list[str]:
    """Ada: compilation_unit wrapper → find with_clause children → selected_component or identifier text."""
    imports = []
    for child in node.named_children:
        if child.type == "with_clause":
            for gc in child.named_children:
                if gc.type == "selected_component":
                    imports.append(source_bytes[gc.start_byte:gc.end_byte].decode("utf-8"))
                elif gc.type == "identifier":
                    imports.append(source_bytes[gc.start_byte:gc.end_byte].decode("utf-8"))
    return imports


ADA_SPEC = LanguageSpec(
    ts_language="ada",
    symbol_node_types={"subprogram_body": "function"},
    name_fields={},
    param_fields={},
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_ada,
    import_node_types=["compilation_unit"],
    extract_import=_make_import_dispatcher({
        "compilation_unit": _extract_import_ada,
    }),
)


# ---------------------------------------------------------------------------
# Pascal custom extractors
# ---------------------------------------------------------------------------

def _extract_name_pascal(node, source_bytes: bytes):
    """Pascal: program → moduleName child → identifier child text.
    defProc → declProc child → identifier child within it."""
    if node.type == "program":
        for child in node.named_children:
            if child.type == "moduleName":
                for gc in child.named_children:
                    if gc.type == "identifier":
                        return source_bytes[gc.start_byte:gc.end_byte].decode("utf-8")
                return None
        return None

    if node.type == "defProc":
        for child in node.named_children:
            if child.type == "declProc":
                for gc in child.named_children:
                    if gc.type == "identifier":
                        return source_bytes[gc.start_byte:gc.end_byte].decode("utf-8")
                return None
        return None

    return None


def _extract_import_pascal(node, source_bytes: bytes) -> list[str]:
    """Pascal: program wrapper → find declUses children → moduleName → identifier text."""
    imports = []
    for child in node.named_children:
        if child.type == "declUses":
            for gc in child.named_children:
                if gc.type == "moduleName":
                    for ggc in gc.named_children:
                        if ggc.type == "identifier":
                            imports.append(source_bytes[ggc.start_byte:ggc.end_byte].decode("utf-8"))
                            break
    return imports


PASCAL_SPEC = LanguageSpec(
    ts_language="pascal",
    symbol_node_types={
        "program": "class",
        "defProc": "function",
    },
    name_fields={},
    param_fields={},
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=["program"],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_pascal,
    import_node_types=["program"],
    extract_import=_make_import_dispatcher({
        "program": _extract_import_pascal,
    }),
)


# ---------------------------------------------------------------------------
# Common Lisp custom extractors
# ---------------------------------------------------------------------------

def _extract_name_commonlisp(node, source_bytes: bytes):
    """Common Lisp: defun → defun_header child → find sym_lit named child (function name).
    AST: defun_header has defun_keyword + sym_lit (name) + list_lit (params)."""
    if node.type == "defun":
        for child in node.named_children:
            if child.type == "defun_header":
                for gc in child.named_children:
                    if gc.type == "sym_lit":
                        return source_bytes[gc.start_byte:gc.end_byte].decode("utf-8")
                return None
        return None

    return None


COMMONLISP_SPEC = LanguageSpec(
    ts_language="commonlisp",
    symbol_node_types={"defun": "function"},
    name_fields={},
    param_fields={},
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_commonlisp,
)


# ---------------------------------------------------------------------------
# Scheme / Racket custom extractors (shared)
# ---------------------------------------------------------------------------

def _resolve_kind_scheme(node, source_bytes: bytes, default_kind: str) -> str | None:
    """Scheme/Racket: list where first symbol child is 'define'.
    If second named child is a list → function.
    If second named child is a symbol → constant.
    Otherwise skip."""
    if node.type != "list":
        return default_kind
    named = node.named_children
    # Find first symbol child
    first_sym = None
    for child in named:
        if child.type == "symbol":
            first_sym = child
            break
    if first_sym is None:
        return None
    text = source_bytes[first_sym.start_byte:first_sym.end_byte].decode("utf-8")
    if text != "define":
        return None
    # Find second named child (skip the 'define' symbol itself)
    idx = named.index(first_sym)
    rest = named[idx + 1:]
    if not rest:
        return None
    second = rest[0]
    if second.type == "list":
        return "function"
    if second.type == "symbol":
        return "constant"
    return None


def _extract_name_scheme(node, source_bytes: bytes):
    """Scheme/Racket: extract name from (define ...) forms.
    Function form: (define (name ...) ...) → first symbol in second child list.
    Constant form: (define name ...) → second named child symbol text."""
    if node.type != "list":
        return None
    named = node.named_children
    # Find first symbol (should be 'define')
    first_sym = None
    for child in named:
        if child.type == "symbol":
            first_sym = child
            break
    if first_sym is None:
        return None
    text = source_bytes[first_sym.start_byte:first_sym.end_byte].decode("utf-8")
    if text != "define":
        return None
    idx = named.index(first_sym)
    rest = named[idx + 1:]
    if not rest:
        return None
    second = rest[0]
    if second.type == "list":
        # (define (name args...) body) — first symbol in the list is the name
        for child in second.named_children:
            if child.type == "symbol":
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8")
        return None
    if second.type == "symbol":
        return source_bytes[second.start_byte:second.end_byte].decode("utf-8")
    return None


SCHEME_SPEC = LanguageSpec(
    ts_language="scheme",
    symbol_node_types={"list": "function"},
    name_fields={},
    param_fields={},
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_scheme,
    resolve_kind=_resolve_kind_scheme,
)


RACKET_SPEC = LanguageSpec(
    ts_language="racket",
    symbol_node_types={"list": "function"},
    name_fields={},
    param_fields={},
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_scheme,
    resolve_kind=_resolve_kind_scheme,
)


# ---------------------------------------------------------------------------
# Tcl custom extractors
# ---------------------------------------------------------------------------

def _extract_name_tcl(node, source_bytes: bytes):
    """Tcl: procedure → first simple_word named child → text."""
    if node.type == "procedure":
        for child in node.named_children:
            if child.type == "simple_word":
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8")
        return None

    return None


TCL_SPEC = LanguageSpec(
    ts_language="tcl",
    symbol_node_types={"procedure": "function"},
    name_fields={},
    param_fields={},
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_tcl,
)


# ---------------------------------------------------------------------------
# Dockerfile custom extractors
# ---------------------------------------------------------------------------

def _extract_name_dockerfile(node, source_bytes: bytes):
    """Dockerfile: from_instruction → image_spec child → image_name child text."""
    if node.type == "from_instruction":
        for child in node.named_children:
            if child.type == "image_spec":
                for gc in child.named_children:
                    if gc.type == "image_name":
                        return source_bytes[gc.start_byte:gc.end_byte].decode("utf-8")
                return None
        return None

    return None


DOCKERFILE_SPEC = LanguageSpec(
    ts_language="dockerfile",
    symbol_node_types={"from_instruction": "class"},
    name_fields={},
    param_fields={},
    return_type_fields={},
    docstring_strategy="",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_dockerfile,
    signature_from_name=True,
)


# ---------------------------------------------------------------------------
# GLSL specification (C-like, reuses _extract_name_c_cpp for functions)
# ---------------------------------------------------------------------------

def _extract_name_glsl(node, source_bytes: bytes):
    """GLSL: function_definition uses C-like declarator drilling.
    struct_specifier → first type_identifier child."""
    if node.type == "function_definition":
        return _extract_name_c_cpp(node, source_bytes)

    if node.type == "struct_specifier":
        for child in node.named_children:
            if child.type == "type_identifier":
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8")
        return None

    return None


GLSL_SPEC = LanguageSpec(
    ts_language="glsl",
    symbol_node_types={
        "function_definition": "function",
        "struct_specifier": "type",
    },
    name_fields={},
    param_fields={},
    return_type_fields={
        "function_definition": "type",
    },
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=["struct_specifier"],
    constant_patterns=[],
    type_patterns=["struct_specifier"],
    call_node_types=["call_expression"],
    extract_name=_extract_name_glsl,
)


# ---------------------------------------------------------------------------
# HLSL specification (C-like, reuses _extract_name_c_cpp for functions)
# ---------------------------------------------------------------------------

HLSL_SPEC = LanguageSpec(
    ts_language="hlsl",
    symbol_node_types={
        "function_definition": "function",
    },
    name_fields={},
    param_fields={},
    return_type_fields={
        "function_definition": "type",
    },
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=[],
    call_node_types=["call_expression"],
    extract_name=_extract_name_c_cpp,
)


# ---------------------------------------------------------------------------
# WGSL custom extractors
# ---------------------------------------------------------------------------

def _extract_name_wgsl(node, source_bytes: bytes):
    """WGSL: function_declaration and struct_declaration → first identifier child."""
    if node.type in ("function_declaration", "struct_declaration"):
        for child in node.named_children:
            if child.type == "identifier":
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8")
        return None

    return None


WGSL_SPEC = LanguageSpec(
    ts_language="wgsl",
    symbol_node_types={
        "function_declaration": "function",
        "struct_declaration": "class",
    },
    name_fields={},
    param_fields={},
    return_type_fields={},
    docstring_strategy="preceding_comment",
    decorator_node_type=None,
    container_node_types=["struct_declaration"],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_wgsl,
)


# ---------------------------------------------------------------------------
# Nix custom extractors
# ---------------------------------------------------------------------------

def _extract_name_nix(node, source_bytes: bytes):
    """Nix: binding → first attrpath or identifier child text."""
    if node.type == "binding":
        for child in node.named_children:
            if child.type in ("attrpath", "identifier"):
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8")
        return None

    return None


NIX_SPEC = LanguageSpec(
    ts_language="nix",
    symbol_node_types={"binding": "constant"},
    name_fields={},
    param_fields={},
    return_type_fields={},
    docstring_strategy="",
    decorator_node_type=None,
    container_node_types=[],
    constant_patterns=[],
    type_patterns=[],
    extract_name=_extract_name_nix,
    signature_from_name=True,
)


# Language registry
LANGUAGE_REGISTRY = {
    "python": PYTHON_SPEC,
    "javascript": JAVASCRIPT_SPEC,
    "typescript": TYPESCRIPT_SPEC,
    "go": GO_SPEC,
    "rust": RUST_SPEC,
    "java": JAVA_SPEC,
    "php": PHP_SPEC,
    "c": C_SPEC,
    "cpp": CPP_SPEC,
    "c_sharp": CSHARP_SPEC,
    "ruby": RUBY_SPEC,
    "swift": SWIFT_SPEC,
    "kotlin": KOTLIN_SPEC,
    "dart": DART_SPEC,
    "perl": PERL_SPEC,
    "lua": LUA_SPEC,
    "bash": BASH_SPEC,
    "scala": SCALA_SPEC,
    "r": R_SPEC,
    "elixir": ELIXIR_SPEC,
    "julia": JULIA_SPEC,
    "clojure": CLOJURE_SPEC,
    "nim": NIM_SPEC,
    "haskell": HASKELL_SPEC,
    "erlang": ERLANG_SPEC,
    "zig": ZIG_SPEC,
    "d": D_SPEC,
    "objc": OBJC_SPEC,
    "ocaml": OCAML_SPEC,
    "fsharp": FSHARP_SPEC,
    "elm": ELM_SPEC,
    "sql": SQL_SPEC,
    "powershell": POWERSHELL_SPEC,
    "solidity": SOLIDITY_SPEC,
    "hcl": HCL_SPEC,
    "proto": PROTO_SPEC,
    "graphql": GRAPHQL_SPEC,
    "css": CSS_SPEC,
    "scss": SCSS_SPEC,
    "html": HTML_SPEC,
    "xml": XML_SPEC,
    "yaml": YAML_SPEC,
    "json": JSON_SPEC,
    "toml": TOML_SPEC,
    "make": MAKE_SPEC,
    "fortran": FORTRAN_SPEC,
    "cmake": CMAKE_SPEC,
    "matlab": MATLAB_SPEC,
    "cuda": CUDA_SPEC,
    "v": V_SPEC,
    "gleam": GLEAM_SPEC,
    "odin": ODIN_SPEC,
    "gdscript": GDSCRIPT_SPEC,
    "verilog": VERILOG_SPEC,
    "vhdl": VHDL_SPEC,
    "ada": ADA_SPEC,
    "pascal": PASCAL_SPEC,
    "commonlisp": COMMONLISP_SPEC,
    "scheme": SCHEME_SPEC,
    "racket": RACKET_SPEC,
    "tcl": TCL_SPEC,
    "dockerfile": DOCKERFILE_SPEC,
    "glsl": GLSL_SPEC,
    "hlsl": HLSL_SPEC,
    "wgsl": WGSL_SPEC,
    "nix": NIX_SPEC,
}
