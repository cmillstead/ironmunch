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
}
