"""Generic AST symbol extractor using tree-sitter.

# SECURITY NOTE: tree-sitter grammars run as C extensions in-process.
# Parsing untrusted source files carries theoretical memory safety risk
# from vulnerabilities in grammar parser C code. Accepted risk: tree-sitter
# grammars are well-tested; in-process parsing is required for performance.
"""

from typing import Optional
from tree_sitter import Language, Parser

# Individual language bindings — only the 7 languages codesight-mcp supports
_LANGUAGE_BINDINGS = {}

_ALLOWED_LANGUAGES = {
    "python", "javascript", "typescript", "go", "rust", "java", "php",
    "c", "cpp", "c_sharp", "ruby", "swift", "kotlin",
}

# Some tree-sitter packages use language_<name>() instead of language()
_LANGUAGE_FUNC_MAP = {
    "typescript": ("tree_sitter_typescript", "language_typescript"),
    "php": ("tree_sitter_php", "language_php"),
    "cpp": ("tree_sitter_cpp", "language"),
    "c_sharp": ("tree_sitter_c_sharp", "language"),
}

def _get_parser(lang_name: str) -> Parser:
    """Get a tree-sitter parser for a language, loading binding on first use."""
    if lang_name not in _ALLOWED_LANGUAGES:
        raise ValueError(f"Unsupported language: {lang_name}")
    if lang_name not in _LANGUAGE_BINDINGS:
        import importlib
        if lang_name in _LANGUAGE_FUNC_MAP:
            mod_name, func_name = _LANGUAGE_FUNC_MAP[lang_name]
        else:
            mod_name = f"tree_sitter_{lang_name}"
            func_name = "language"
        try:
            mod = importlib.import_module(mod_name)
        except ImportError:
            raise ImportError(
                f"tree-sitter binding for '{lang_name}' not installed. "
                f"Install: pip install tree-sitter-{lang_name}"
            )
        _LANGUAGE_BINDINGS[lang_name] = Language(getattr(mod, func_name)())
    parser = Parser(_LANGUAGE_BINDINGS[lang_name])
    return parser

from .symbols import Symbol, make_symbol_id, compute_content_hash
from .languages import LanguageSpec, LANGUAGE_REGISTRY
from ..security import sanitize_signature_for_api


def parse_file(content: str, filename: str, language: str) -> list[Symbol]:
    """Parse source code and extract symbols using tree-sitter.

    Args:
        content: Raw source code
        filename: File path (for ID generation)
        language: Language name (must be in LANGUAGE_REGISTRY)

    Returns:
        List of Symbol objects
    """
    if language not in LANGUAGE_REGISTRY:
        return []

    spec = LANGUAGE_REGISTRY[language]
    source_bytes = content.encode("utf-8")

    # Get parser for this language
    parser = _get_parser(spec.ts_language)
    tree = parser.parse(source_bytes)

    symbols = []
    _walk_tree(tree.root_node, spec, source_bytes, filename, language, symbols, None)

    # Extract file-level imports and attach to all top-level symbols
    if spec.import_node_types:
        file_imports = _extract_imports(tree.root_node, spec, source_bytes)
        if file_imports:
            for sym in symbols:
                if sym.parent is None:
                    sym.imports = file_imports

    # Disambiguate overloaded symbols (same ID)
    symbols = _disambiguate_overloads(symbols)

    return symbols


def _walk_tree(
    node,
    spec: LanguageSpec,
    source_bytes: bytes,
    filename: str,
    language: str,
    symbols: list,
    parent_symbol: Optional[Symbol] = None
):
    """Recursively walk the AST and extract symbols."""
    # Check if this node is a symbol
    if node.type in spec.symbol_node_types:
        symbol = _extract_symbol(
            node, spec, source_bytes, filename, language, parent_symbol
        )
        if symbol:
            symbols.append(symbol)
            parent_symbol = symbol

    # Check for constant patterns (top-level assignments with UPPER_CASE names)
    if node.type in spec.constant_patterns and parent_symbol is None:
        const_symbol = _extract_constant(node, spec, source_bytes, filename, language)
        if const_symbol:
            symbols.append(const_symbol)

    # Recurse into children
    for child in node.children:
        _walk_tree(child, spec, source_bytes, filename, language, symbols, parent_symbol)


def _extract_symbol(
    node,
    spec: LanguageSpec,
    source_bytes: bytes,
    filename: str,
    language: str,
    parent_symbol: Optional[Symbol] = None
) -> Optional[Symbol]:
    """Extract a Symbol from an AST node."""
    kind = spec.symbol_node_types[node.type]

    # Skip nodes with errors
    if node.has_error:
        return None

    # Extract name
    name = _extract_name(node, spec, source_bytes)
    if not name:
        return None

    # Build qualified name
    if parent_symbol:
        qualified_name = f"{parent_symbol.name}.{name}"
        kind = "method" if kind == "function" else kind
    else:
        qualified_name = name

    # Build signature and sanitize secrets at parse time (SEC-HIGH-1)
    signature = sanitize_signature_for_api(_build_signature(node, spec, source_bytes))

    # Extract docstring and sanitize secrets at parse time (SEC-HIGH-1)
    docstring = sanitize_signature_for_api(_extract_docstring(node, spec, source_bytes))

    # Extract decorators
    decorators = _extract_decorators(node, spec, source_bytes)

    # Compute content hash
    symbol_bytes = source_bytes[node.start_byte:node.end_byte]
    c_hash = compute_content_hash(symbol_bytes)

    # Extract function calls from function/method bodies
    calls = []
    if kind in ("function", "method") and spec.call_node_types:
        body = node.child_by_field_name("body")
        if body:
            calls = _extract_calls(body, spec, source_bytes)

    # Extract inheritance and implementation for class nodes
    inherits_from = []
    implements = []
    if kind in ("class", "type"):
        inherits_from, implements = _extract_bases(node, spec, source_bytes)

    # Create symbol
    symbol = Symbol(
        id=make_symbol_id(filename, qualified_name, kind),
        file=filename,
        name=name,
        qualified_name=qualified_name,
        kind=kind,
        language=language,
        signature=signature,
        docstring=docstring,
        decorators=decorators,
        parent=parent_symbol.id if parent_symbol else None,
        line=node.start_point[0] + 1,
        end_line=node.end_point[0] + 1,
        byte_offset=node.start_byte,
        byte_length=node.end_byte - node.start_byte,
        content_hash=c_hash,
        calls=calls,
        inherits_from=inherits_from,
        implements=implements,
    )

    return symbol


def _extract_name(node, spec: LanguageSpec, source_bytes: bytes) -> Optional[str]:
    """Extract the name from an AST node."""
    # Handle special cases first
    if node.type == "arrow_function":
        # Arrow functions get name from parent variable_declarator
        return None

    # Handle type_declaration in Go - name is in type_spec child
    if node.type == "type_declaration":
        for child in node.children:
            if child.type == "type_spec":
                name_node = child.child_by_field_name("name")
                if name_node:
                    return source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8")
        return None

    # C/C++: function_definition uses declarator -> function_declarator -> declarator
    if node.type == "function_definition" and node.type not in spec.name_fields:
        decl = node.child_by_field_name("declarator")
        if decl:
            # May be function_declarator directly, or pointer_declarator wrapping it
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

    # C/C++: type_definition uses declarator for the typedef name
    if node.type == "type_definition" and node.type not in spec.name_fields:
        decl = node.child_by_field_name("declarator")
        if decl:
            return source_bytes[decl.start_byte:decl.end_byte].decode("utf-8")
        return None

    if node.type not in spec.name_fields:
        return None

    field_name = spec.name_fields[node.type]
    name_node = node.child_by_field_name(field_name)

    if name_node:
        return source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8")

    return None


def _build_signature(node, spec: LanguageSpec, source_bytes: bytes) -> str:
    """Build a clean signature from AST node."""
    # Find the body child to determine where signature ends
    body = node.child_by_field_name("body")

    if body:
        # Signature is from start of node to start of body
        end_byte = body.start_byte
    else:
        end_byte = node.end_byte

    sig_bytes = source_bytes[node.start_byte:end_byte]
    sig_text = sig_bytes.decode("utf-8").strip()

    # Clean up: remove trailing '{', ':', etc.
    sig_text = sig_text.rstrip("{: \n\t")

    return sig_text


def _extract_docstring(node, spec: LanguageSpec, source_bytes: bytes) -> str:
    """Extract docstring using language-specific strategy."""
    if spec.docstring_strategy == "next_sibling_string":
        return _extract_python_docstring(node, source_bytes)
    elif spec.docstring_strategy == "preceding_comment":
        return _extract_preceding_comments(node, source_bytes)
    return ""


def _extract_python_docstring(node, source_bytes: bytes) -> str:
    """Extract Python docstring from first statement in body."""
    body = node.child_by_field_name("body")
    if not body or body.child_count == 0:
        return ""

    # Find first expression_statement in body (function docstrings)
    for child in body.children:
        if child.type == "expression_statement":
            # Check if it's a string
            expr = child.child_by_field_name("expression")
            if expr and expr.type == "string":
                doc = source_bytes[expr.start_byte:expr.end_byte].decode("utf-8")
                return _strip_quotes(doc)
            # Handle tree-sitter-python 0.21+ string format
            if child.child_count > 0:
                first = child.children[0]
                if first.type in ("string", "concatenated_string"):
                    doc = source_bytes[first.start_byte:first.end_byte].decode("utf-8")
                    return _strip_quotes(doc)
        # Class docstrings are directly string nodes in the block
        elif child.type == "string":
            doc = source_bytes[child.start_byte:child.end_byte].decode("utf-8")
            return _strip_quotes(doc)

    return ""


def _strip_quotes(text: str) -> str:
    """Strip quotes from a docstring."""
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


def _extract_preceding_comments(node, source_bytes: bytes) -> str:
    """Extract comments that immediately precede a node."""
    comments = []

    # Walk backwards through siblings
    prev = node.prev_named_sibling
    while prev and prev.type in ("comment", "line_comment", "block_comment"):
        comment_text = source_bytes[prev.start_byte:prev.end_byte].decode("utf-8")
        comments.insert(0, comment_text)
        prev = prev.prev_named_sibling

    if not comments:
        return ""

    docstring = "\n".join(comments)
    return _clean_comment_markers(docstring)


def _clean_comment_markers(text: str) -> str:
    """Clean comment markers from docstring."""
    lines = text.split("\n")
    cleaned = []

    for line in lines:
        line = line.strip()
        # Remove leading comment markers
        if line.startswith("/**"):
            line = line[3:]
        elif line.startswith("/*"):
            line = line[2:]
        elif line.startswith("//!"):
            line = line[3:]
        elif line.startswith("///"):
            line = line[3:]
        elif line.startswith("//"):
            line = line[2:]
        elif line.startswith("*"):
            line = line[1:]

        # Remove trailing */
        if line.endswith("*/"):
            line = line[:-2]

        cleaned.append(line.strip())

    return "\n".join(cleaned).strip()


def _extract_decorators(node, spec: LanguageSpec, source_bytes: bytes) -> list[str]:
    """Extract decorators/attributes from a node."""
    if not spec.decorator_node_type:
        return []

    decorators = []

    # Walk backwards through siblings to find decorators
    prev = node.prev_named_sibling
    while prev and prev.type == spec.decorator_node_type:
        decorator_text = source_bytes[prev.start_byte:prev.end_byte].decode("utf-8")
        # Sanitize secrets in decorator arguments at parse time (SEC-MED-1)
        decorators.insert(0, sanitize_signature_for_api(decorator_text.strip()))
        prev = prev.prev_named_sibling

    return decorators


def _extract_constant(
    node, spec: LanguageSpec, source_bytes: bytes, filename: str, language: str
) -> Optional[Symbol]:
    """Extract a constant (UPPER_CASE top-level assignment)."""
    # Only extract constants at module level for Python
    if node.type == "assignment":
        left = node.child_by_field_name("left")
        if left and left.type == "identifier":
            name = source_bytes[left.start_byte:left.end_byte].decode("utf-8")
            # Check if UPPER_CASE (constant convention)
            if name.isupper() or (len(name) > 1 and name[0].isupper() and "_" in name):
                # Get the full assignment text as signature
                sig = source_bytes[node.start_byte:node.end_byte].decode("utf-8").strip()
                const_bytes = source_bytes[node.start_byte:node.end_byte]
                c_hash = compute_content_hash(const_bytes)

                return Symbol(
                    id=make_symbol_id(filename, name, "constant"),
                    file=filename,
                    name=name,
                    qualified_name=name,
                    kind="constant",
                    language=language,
                    signature=sanitize_signature_for_api(sig)[:100],  # Redact secrets, then truncate
                    line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    byte_offset=node.start_byte,
                    byte_length=node.end_byte - node.start_byte,
                    content_hash=c_hash,
                )

    return None


def _extract_callee_name(node, source_bytes: bytes) -> Optional[str]:
    """Extract the callee name from a call expression's function child.

    Handles simple calls (foo()), attribute/member calls (obj.method()),
    scoped calls (mod::func()), and Java method invocations.
    """
    if node.type == "identifier":
        return source_bytes[node.start_byte:node.end_byte].decode("utf-8")

    # Python attribute access: obj.method
    if node.type == "attribute":
        attr = node.child_by_field_name("attribute")
        if attr:
            return source_bytes[attr.start_byte:attr.end_byte].decode("utf-8")

    # JS/TS member_expression: obj.property
    if node.type == "member_expression":
        prop = node.child_by_field_name("property")
        if prop:
            return source_bytes[prop.start_byte:prop.end_byte].decode("utf-8")

    # Go selector_expression: pkg.Func
    if node.type == "selector_expression":
        field_node = node.child_by_field_name("field")
        if field_node:
            return source_bytes[field_node.start_byte:field_node.end_byte].decode("utf-8")

    # Rust scoped_identifier: module::func
    if node.type == "scoped_identifier":
        name_node = node.child_by_field_name("name")
        if name_node:
            return source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8")

    # Rust field_expression: obj.method (for method calls)
    if node.type == "field_expression":
        field_node = node.child_by_field_name("field")
        if field_node:
            return source_bytes[field_node.start_byte:field_node.end_byte].decode("utf-8")

    # C# member_access_expression: obj.Method
    if node.type == "member_access_expression":
        name_node = node.child_by_field_name("name")
        if name_node:
            return source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8")

    # Ruby call: obj.method — method field
    if node.type == "call":
        method_node = node.child_by_field_name("method")
        if method_node:
            return source_bytes[method_node.start_byte:method_node.end_byte].decode("utf-8")

    # Swift/Kotlin navigation_expression: obj.method
    if node.type == "navigation_expression":
        # Last named child is typically the member name
        for child in reversed(node.named_children):
            if child.type in ("simple_identifier", "identifier"):
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8")

    # Simple identifier fallback (Swift, Kotlin, Ruby)
    if node.type in ("simple_identifier", "constant"):
        return source_bytes[node.start_byte:node.end_byte].decode("utf-8")

    return None


def _extract_calls(body_node, spec: LanguageSpec, source_bytes: bytes) -> list[str]:
    """Walk a symbol's body AST and extract function/method call names."""
    calls = []
    _collect_calls(body_node, spec, source_bytes, calls)
    # Deduplicate while preserving order
    seen = set()
    deduped = []
    for name in calls:
        if name not in seen:
            seen.add(name)
            deduped.append(name)
    return deduped


def _collect_calls(node, spec: LanguageSpec, source_bytes: bytes, calls: list):
    """Recursively collect call names from AST nodes."""
    if node.type in spec.call_node_types:
        # Java method_invocation: name field is the method identifier
        if node.type == "method_invocation":
            name_node = node.child_by_field_name("name")
            if name_node:
                name = source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8")
                calls.append(name)
        # Rust macro_invocation: extract macro name
        elif node.type == "macro_invocation":
            macro_node = node.child_by_field_name("macro")
            if macro_node:
                name = source_bytes[macro_node.start_byte:macro_node.end_byte].decode("utf-8")
                calls.append(name)
        # PHP function_call_expression / member_call_expression
        elif node.type == "member_call_expression":
            name_node = node.child_by_field_name("name")
            if name_node:
                name = source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8")
                calls.append(name)
        elif node.type == "function_call_expression":
            func_node = node.child_by_field_name("function")
            if func_node:
                name = _extract_callee_name(func_node, source_bytes)
                if name:
                    calls.append(name)
        # C# invocation_expression: func() or obj.Method()
        elif node.type == "invocation_expression":
            func_node = node.child_by_field_name("function")
            if func_node:
                name = _extract_callee_name(func_node, source_bytes)
                if name:
                    calls.append(name)
            else:
                # Fallback: first named child is the callee
                for child in node.named_children:
                    name = _extract_callee_name(child, source_bytes)
                    if name:
                        calls.append(name)
                        break
        # Ruby call: obj.method(args)
        elif node.type == "call" and "call" in spec.call_node_types:
            method_node = node.child_by_field_name("method")
            if method_node:
                name = source_bytes[method_node.start_byte:method_node.end_byte].decode("utf-8")
                calls.append(name)
        else:
            # Generic: call / call_expression — extract function child
            func_node = node.child_by_field_name("function")
            if func_node:
                name = _extract_callee_name(func_node, source_bytes)
                if name:
                    calls.append(name)

    # Recurse into children
    for child in node.children:
        _collect_calls(child, spec, source_bytes, calls)


def _extract_imports(root_node, spec: LanguageSpec, source_bytes: bytes) -> list[str]:
    """Extract file-level imports from the top-level AST nodes.

    Delegates per-node-type extraction to spec.extract_import, which is
    a callable provided by the LanguageSpec for each language.
    """
    if not spec.extract_import:
        return []

    imports = []

    for child in root_node.children:
        if child.type not in spec.import_node_types:
            continue

        names = spec.extract_import(child, source_bytes)
        imports.extend(names)

    # Deduplicate while preserving order
    seen = set()
    deduped = []
    for name in imports:
        if name not in seen:
            seen.add(name)
            deduped.append(name)
    return deduped


def _extract_bases(
    node, spec: LanguageSpec, source_bytes: bytes
) -> tuple[list[str], list[str]]:
    """Extract inheritance and implementation names from a class/type node.

    Returns:
        (inherits_from, implements) — both lists of unresolved names.
    """
    inherits_from = []
    implements = []

    # Extract inheritance (superclasses / base classes)
    for field_name in spec.inheritance_fields:
        _collect_type_names_from_field(node, field_name, source_bytes, inherits_from, spec)

    # Extract implementations (interfaces)
    for field_name in spec.implementation_fields:
        _collect_type_names_from_field(node, field_name, source_bytes, implements, spec)

    # Deduplicate
    inherits_from = list(dict.fromkeys(inherits_from))
    implements = list(dict.fromkeys(implements))

    return inherits_from, implements


def _collect_type_names_from_field(
    node, field_name: str, source_bytes: bytes, result: list, spec: LanguageSpec = None
):
    """Collect type/class names from a node's child field.

    Delegates per-child-type extraction to spec.collect_type_names when available,
    falling back to extracting identifiers from all named children.
    """
    # Try child_by_field_name first
    child = node.child_by_field_name(field_name)

    # If not found as a field, search named children by type
    if child is None:
        for c in node.named_children:
            if c.type == field_name:
                child = c
                break

    if child is None:
        return

    # Delegate to per-language collector if available
    if spec is not None and spec.collect_type_names is not None:
        names = spec.collect_type_names(child, source_bytes, _extract_type_identifier)
        result.extend(names)
        return

    # Fallback: try to extract identifiers from all named children
    for type_child in child.named_children:
        name = _extract_type_identifier(type_child, source_bytes)
        if name:
            result.append(name)


def _extract_type_identifier(node, source_bytes: bytes) -> Optional[str]:
    """Extract a type name from an AST node.

    Handles identifier, type_identifier, attribute (Python dotted names),
    generic_type, scoped_type_identifier, qualified_name, and name nodes.
    """
    if node.type in ("identifier", "type_identifier", "constant", "simple_identifier"):
        return source_bytes[node.start_byte:node.end_byte].decode("utf-8")

    # Swift/Kotlin user_type: contains type_identifier or simple_identifier
    if node.type == "user_type":
        for child in node.named_children:
            if child.type in ("type_identifier", "simple_identifier", "identifier"):
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8")

    # Kotlin constructor_invocation: Bar() — extract the type name
    if node.type == "constructor_invocation":
        for child in node.named_children:
            if child.type in ("user_type", "identifier", "simple_identifier"):
                name = _extract_type_identifier(child, source_bytes)
                if name:
                    return name

    # Python dotted name: foo.Bar
    if node.type == "attribute":
        return source_bytes[node.start_byte:node.end_byte].decode("utf-8")

    # Generic type: List<T> — extract the base type name
    if node.type == "generic_type":
        for child in node.named_children:
            if child.type in ("identifier", "type_identifier"):
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8")
            if child.type == "scoped_type_identifier":
                return source_bytes[child.start_byte:child.end_byte].decode("utf-8")

    # Scoped type: path::Type
    if node.type == "scoped_type_identifier":
        name_node = node.child_by_field_name("name")
        if name_node:
            return source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8")

    # PHP qualified_name or name
    if node.type in ("qualified_name", "name"):
        return source_bytes[node.start_byte:node.end_byte].decode("utf-8")

    return None


def _disambiguate_overloads(symbols: list[Symbol]) -> list[Symbol]:
    """Append ordinal suffix to symbols with duplicate IDs.

    E.g., if two symbols have ID "file.py::foo#function", they become
    "file.py::foo#function~1" and "file.py::foo#function~2".
    """
    from collections import Counter

    id_counts = Counter(s.id for s in symbols)
    # Only process IDs that appear more than once
    duplicated = {sid for sid, count in id_counts.items() if count > 1}

    if not duplicated:
        return symbols

    # Track ordinals per duplicate ID
    ordinals: dict[str, int] = {}
    result = []
    for sym in symbols:
        if sym.id in duplicated:
            ordinals[sym.id] = ordinals.get(sym.id, 0) + 1
            sym.id = f"{sym.id}~{ordinals[sym.id]}"
        result.append(sym)
    return result
