"""Language-agnostic AST complexity extraction via tree-sitter node types.

Computes cyclomatic complexity, cognitive complexity, max nesting depth,
parameter count, and lines of code from a tree-sitter AST node.

Uses a generic set of branch node types that works across most tree-sitter
grammars, with per-language overrides for language-specific constructs.
"""


# Node types that represent branching decisions (common across grammars).
_BRANCH_NODES: frozenset[str] = frozenset({
    # Conditionals
    "if_statement", "if_expression", "elif_clause", "else_if_clause",
    "conditional_expression", "ternary_expression",
    # Loops
    "for_statement", "for_expression", "for_in_statement",
    "while_statement", "while_expression", "do_statement",
    # Exception handling
    "except_clause", "catch_clause", "rescue",
    # Pattern matching / switch
    "case_clause", "match_arm", "switch_case",
    "when_clause", "when_entry",
})

# Node types that create a new nesting level.
_NESTING_NODES: frozenset[str] = frozenset({
    "if_statement", "if_expression",
    "for_statement", "for_expression", "for_in_statement",
    "while_statement", "while_expression", "do_statement",
    "try_statement", "try_expression",
    "except_clause", "catch_clause", "rescue",
    "match_expression", "switch_statement", "switch_expression",
    "case_clause", "match_arm", "switch_case",
    "with_statement",
    "closure_expression", "lambda",
})

# Language-specific additions to branch nodes.
_LANGUAGE_BRANCH_EXTRAS: dict[str, frozenset[str]] = {
    "go": frozenset({
        "select_statement", "type_switch_statement", "comm_clause",
        "expression_case",
    }),
    "rust": frozenset({
        "match_expression", "if_let_expression", "while_let_expression",
    }),
    "kotlin": frozenset({
        "when_expression", "when_entry",
    }),
    "swift": frozenset({
        "switch_statement", "case_item",
    }),
    "ruby": frozenset({
        "case", "when_clause", "rescue", "unless",
    }),
    "erlang": frozenset({
        "case_expr", "if_expr", "receive_expr",
    }),
    "scala": frozenset({
        "match_expression", "case_clause",
    }),
    "haskell": frozenset({
        "alternative", "guards",
    }),
    "lua": frozenset({
        "repeat_statement",
    }),
}

# Language-specific additions to nesting nodes.
_LANGUAGE_NESTING_EXTRAS: dict[str, frozenset[str]] = {
    "go": frozenset({"select_statement", "type_switch_statement"}),
    "rust": frozenset({"match_expression", "if_let_expression", "while_let_expression"}),
    "kotlin": frozenset({"when_expression"}),
    "erlang": frozenset({"case_expr", "if_expr", "receive_expr"}),
    "scala": frozenset({"match_expression"}),
    "haskell": frozenset({"alternative"}),
    "lua": frozenset({"repeat_statement"}),
}

# Node types for boolean operators that add to cyclomatic complexity.
_BOOLEAN_OPERATOR_NODES: frozenset[str] = frozenset({
    "boolean_operator",   # Python: and/or
    "binary_expression",  # JS/TS/Java/Go etc. — filtered by operator below
})

# Operators within binary_expression that count as branch points.
_BOOLEAN_OPERATORS: frozenset[str] = frozenset({"&&", "||", "and", "or"})

# Node types that hold parameters.
_PARAM_CONTAINER_TYPES: frozenset[str] = frozenset({
    "parameters", "formal_parameters", "parameter_list",
    "function_type_parameters", "lambda_parameters",
})

# Individual parameter node types.
_PARAM_NODE_TYPES: frozenset[str] = frozenset({
    "identifier",              # Python: def f(a, b)
    "typed_parameter",         # Python: def f(a: int)
    "default_parameter",       # Python: def f(a=1)
    "typed_default_parameter", # Python: def f(a: int = 1)
    "list_splat_pattern",      # Python: *args
    "dictionary_splat_pattern",# Python: **kwargs
    "parameter_declaration",   # Go, C, Java
    "required_parameter",      # TS/JS
    "optional_parameter",      # TS/JS
    "rest_parameter",          # JS: ...args
    "simple_parameter",        # Ruby
    "formal_parameter",        # Java/Kotlin
    "function_value_parameter",# Kotlin
    "parameter",               # generic
})


def _get_branch_nodes(language: str) -> frozenset[str]:
    """Return branch nodes for a language (generic + extras)."""
    extras = _LANGUAGE_BRANCH_EXTRAS.get(language, frozenset())
    return _BRANCH_NODES | extras


def _get_nesting_nodes(language: str) -> frozenset[str]:
    """Return nesting nodes for a language (generic + extras)."""
    extras = _LANGUAGE_NESTING_EXTRAS.get(language, frozenset())
    return _NESTING_NODES | extras


def _is_boolean_branch(node) -> bool:
    """Return True if node is a boolean operator that adds to cyclomatic complexity."""
    if node.type == "boolean_operator":
        return True
    if node.type == "binary_expression":
        # Check operator child
        for child in node.children:
            if child.type in _BOOLEAN_OPERATORS:
                return True
            # Some grammars use named operator nodes
            if child.is_named and child.type in ("&&", "||"):
                return True
    return False


def _count_params(node) -> int:
    """Count parameters of a function node."""
    for child in node.children:
        if child.type in _PARAM_CONTAINER_TYPES:
            count = 0
            for param in child.children:
                if param.type in _PARAM_NODE_TYPES:
                    count += 1
            return count
    return 0


def compute_complexity(node, language: str) -> dict:
    """Compute complexity metrics from a tree-sitter AST node.

    Args:
        node: A tree-sitter Node (the function/method node). May be None.
        language: Language name (e.g., "python", "go").

    Returns:
        Dict with keys: cyclomatic, cognitive, max_nesting, param_count, loc.
    """
    empty = {
        "cyclomatic": 1,
        "cognitive": 0,
        "max_nesting": 0,
        "param_count": 0,
        "loc": 0,
    }
    if node is None:
        return empty

    branch_nodes = _get_branch_nodes(language)
    nesting_nodes = _get_nesting_nodes(language)

    cyclomatic = 1
    cognitive = 0
    max_nesting = 0

    _MAX_WALK_DEPTH = 500

    def walk(n, nesting_depth: int, _depth: int = 0) -> None:
        nonlocal cyclomatic, cognitive, max_nesting

        # ADV-MED-8: Cap recursion depth to prevent stack overflow on deep ASTs.
        if _depth >= _MAX_WALK_DEPTH:
            return

        if n.type in branch_nodes:
            cyclomatic += 1
            cognitive += 1 + nesting_depth

        if _is_boolean_branch(n) and n.type not in branch_nodes:
            cyclomatic += 1
            cognitive += 1

        is_nesting = n.type in nesting_nodes
        new_depth = nesting_depth + 1 if is_nesting else nesting_depth
        if new_depth > max_nesting:
            max_nesting = new_depth

        for child in n.children:
            walk(child, new_depth, _depth + 1)

    # Walk the body, not the full function node (avoids counting the function itself)
    body = node.child_by_field_name("body")
    if body:
        walk(body, 0)
    else:
        # Some languages (Rust, Go) may not have a named "body" field
        # Walk all children except parameter lists
        for child in node.children:
            if child.type not in _PARAM_CONTAINER_TYPES:
                walk(child, 0)

    param_count = _count_params(node)
    loc = node.end_point[0] - node.start_point[0] + 1

    return {
        "cyclomatic": cyclomatic,
        "cognitive": cognitive,
        "max_nesting": max_nesting,
        "param_count": param_count,
        "loc": loc,
    }
