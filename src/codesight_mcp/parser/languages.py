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
    import_node_types=[],  # Julia uses using/import statements — TODO: add if needed
    extract_name=_extract_name_julia,
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
    import_node_types=[],  # Nim uses import/include statements — TODO: add if needed
    extract_name=_extract_name_nim,
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
    import_node_types=[],  # Haskell uses import statements — TODO: add if needed
    resolve_kind=_resolve_kind_haskell,
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
    call_node_types=[],  # D function calls — skip for now
    import_node_types=[],  # D uses import statements — TODO: add if needed
    extract_name=_extract_name_d,
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
    call_node_types=[],  # ObjC message sends — complex, skip for now
    import_node_types=[],  # ObjC uses #import — similar to C includes
    extract_name=_extract_name_objc,
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
    import_node_types=[],  # OCaml uses open statements — TODO: add if needed
    extract_name=_extract_name_ocaml,
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
    import_node_types=[],  # F# uses open statements — TODO: add if needed
    extract_name=_extract_name_fsharp,
    resolve_kind=_resolve_kind_fsharp,
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
    import_node_types=[],  # Elm uses import statements — TODO: add if needed
    extract_name=_extract_name_elm,
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
}
