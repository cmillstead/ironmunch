"""Security rule engine -- detects dangerous API usage via indexed calls+imports.

Scans symbol data (calls, imports, language) against a declarative rule set
to identify potential security hotspots. Two matching strategies:

1. Calls-only (imports_any empty): match if ANY call name is in symbol calls.
2. Import-assisted (imports_any non-empty): match if ANY import AND ANY call match.

For nested symbols (methods) whose imports list is empty, a file-level
import fallback is used so that ``os.system`` inside a method is still
detected when ``os`` is imported at module level.
"""

from dataclasses import dataclass
from typing import Callable

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass(frozen=True)
class SecurityRule:
    """A single security detection rule."""

    id: str
    name: str
    severity: str          # critical, high, medium, low
    confidence: str        # high, medium, low
    description: str
    remediation: str
    owasp: list[str]       # ["A03:2021"]
    cwe: list[str]         # ["CWE-94"]
    languages: list[str]   # ["python"] or ["*"]
    calls_any: frozenset[str]    # Bare call names to match
    imports_any: frozenset[str]  # Import names (empty = calls-only rule)
    arg_checker: Callable | None = None   # (tree, source_bytes) -> bool
    supersedes: str | None = None         # Rule ID this rule replaces


@dataclass(frozen=True)
class ModuleLevelRule:
    """A module-level assignment detection rule."""

    id: str
    name: str
    severity: str
    confidence: str
    description: str
    remediation: str
    owasp: list[str]
    cwe: list[str]
    target_name: str          # Variable name to match (e.g., "DEBUG")
    dangerous_value: str | None = None  # Exact literal to match; None = any non-empty string literal


# ---------------------------------------------------------------------------
# AST argument checking infrastructure
# ---------------------------------------------------------------------------


def _parse_and_check_args(
    source_bytes: bytes, lang_name: str, arg_checker: Callable,
) -> tuple[bool, bool]:
    """Parse source and run arg checker.

    Returns (checker_succeeded, is_dangerous).
    """
    try:
        from tree_sitter_language_pack import get_parser  # noqa: F811
    except ImportError:
        return (False, False)

    try:
        parser = get_parser(lang_name)
    except (KeyError, ValueError):
        return (False, False)

    tree = parser.parse(source_bytes)
    if tree is None or tree.root_node is None:
        return (False, False)

    try:
        result = arg_checker(tree, source_bytes)
    except Exception:  # noqa: BLE001 — checker may fail on unexpected AST shapes
        return (False, False)

    return (True, bool(result))


def _check_shell_true(tree: object, source_bytes: bytes) -> bool:
    """Check for shell=True in subprocess calls."""
    def _walk(node: object) -> bool:
        if node.type == "call":
            for child in node.children:
                if child.type == "argument_list":
                    for arg in child.children:
                        if arg.type == "keyword_argument":
                            name_node = arg.child_by_field_name("name")
                            value_node = arg.child_by_field_name("value")
                            if (
                                name_node is not None
                                and value_node is not None
                                and name_node.text.decode() == "shell"
                                and value_node.text.decode() == "True"
                            ):
                                return True
        for child in node.children:
            if _walk(child):
                return True
        return False

    return _walk(tree.root_node)


def _check_yaml_unsafe_loader(tree: object, source_bytes: bytes) -> bool:
    """Check for yaml.load() without SafeLoader."""
    _safe_loaders = {"SafeLoader", "CSafeLoader", "yaml.SafeLoader", "yaml.CSafeLoader"}

    def _walk(node: object) -> bool:
        if node.type == "call":
            func_node = node.child_by_field_name("function")
            if func_node is not None:
                func_text = func_node.text.decode()
                # Match "load" calls but not safe_load, dump, etc.
                bare_name = func_text.rsplit(".", 1)[-1]
                if bare_name == "load":
                    args_node = node.child_by_field_name("arguments")
                    if args_node is not None:
                        has_loader_kw = False
                        loader_safe = False
                        for arg in args_node.children:
                            if arg.type == "keyword_argument":
                                name_node = arg.child_by_field_name("name")
                                value_node = arg.child_by_field_name("value")
                                if (
                                    name_node is not None
                                    and name_node.text.decode() == "Loader"
                                ):
                                    has_loader_kw = True
                                    if (
                                        value_node is not None
                                        and value_node.text.decode() in _safe_loaders
                                    ):
                                        loader_safe = True
                        if not has_loader_kw:
                            return True  # No Loader keyword: dangerous
                        if not loader_safe:
                            return True  # Loader not in safe allowlist
        for child in node.children:
            if _walk(child):
                return True
        return False

    return _walk(tree.root_node)


def _check_bind_all_interfaces(tree: object, source_bytes: bytes) -> bool:
    """Check for binding to 0.0.0.0."""
    def _walk(node: object) -> bool:
        if node.type == "call":
            func_node = node.child_by_field_name("function")
            if func_node is not None:
                func_text = func_node.text.decode()
                bare_name = func_text.rsplit(".", 1)[-1]

                if bare_name == "bind":
                    # Check first positional arg (tuple with host as first element)
                    args_node = node.child_by_field_name("arguments")
                    if args_node is not None:
                        for arg in args_node.children:
                            if arg.type == "tuple":
                                # Find first string element (skip punctuation nodes)
                                for elem in arg.children:
                                    if elem.type == "string":
                                        if "0.0.0.0" in elem.text.decode():
                                            return True
                                        break  # Only check first string element

                elif bare_name in ("run", "run_simple"):
                    # Check host= keyword argument
                    args_node = node.child_by_field_name("arguments")
                    if args_node is not None:
                        for arg in args_node.children:
                            if arg.type == "keyword_argument":
                                name_node = arg.child_by_field_name("name")
                                value_node = arg.child_by_field_name("value")
                                if (
                                    name_node is not None
                                    and value_node is not None
                                    and name_node.text.decode() == "host"
                                    and "0.0.0.0" in value_node.text.decode()
                                ):
                                    return True

        for child in node.children:
            if _walk(child):
                return True
        return False

    return _walk(tree.root_node)


def _check_debug_true(tree: object, source_bytes: bytes) -> bool:
    """Check for debug=True in run/run_simple calls."""
    def _walk(node: object) -> bool:
        if node.type == "call":
            func_node = node.child_by_field_name("function")
            if func_node is not None:
                func_text = func_node.text.decode()
                bare_name = func_text.rsplit(".", 1)[-1]
                if bare_name in ("run", "run_simple"):
                    args_node = node.child_by_field_name("arguments")
                    if args_node is not None:
                        for arg in args_node.children:
                            if arg.type == "keyword_argument":
                                name_node = arg.child_by_field_name("name")
                                value_node = arg.child_by_field_name("value")
                                if (
                                    name_node is not None
                                    and value_node is not None
                                    and name_node.text.decode() == "debug"
                                    and value_node.text.decode() == "True"
                                ):
                                    return True
        for child in node.children:
            if _walk(child):
                return True
        return False

    return _walk(tree.root_node)


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

RULES: list[SecurityRule] = [
    SecurityRule(
        id="SEC-001",
        name="eval() usage",
        severity="critical",
        confidence="high",
        description="eval() runs arbitrary code from string input",
        remediation="Use ast.literal_eval() for safe evaluation of literals",
        owasp=["A03:2021"],
        cwe=["CWE-94"],
        languages=["*"],
        calls_any=frozenset({"eval"}),
        imports_any=frozenset(),
    ),
    SecurityRule(
        id="SEC-002",
        name="exec() usage",
        severity="critical",
        confidence="high",
        description="exec() runs arbitrary Python code from string input",
        remediation="Avoid exec(); use safer alternatives or sandboxed runtime",
        owasp=["A03:2021"],
        cwe=["CWE-94"],
        languages=["python"],
        calls_any=frozenset({"exec"}),
        imports_any=frozenset(),
    ),
    SecurityRule(
        id="SEC-003",
        name="os.system/popen usage",
        severity="critical",
        confidence="high",
        description="os.system/popen runs shell commands with no escaping",
        remediation="Use subprocess.run() with shell=False and a list of arguments",
        owasp=["A03:2021"],
        cwe=["CWE-78"],
        languages=["python"],
        calls_any=frozenset({"system", "popen"}),
        imports_any=frozenset({"os"}),
    ),
    SecurityRule(
        id="SEC-004",
        name="subprocess usage",
        severity="high",
        confidence="medium",
        description="subprocess calls may run arbitrary commands if inputs are unsanitized",
        remediation="Use subprocess.run() with shell=False, validate inputs, avoid shell=True",
        owasp=["A03:2021"],
        cwe=["CWE-78"],
        languages=["python"],
        calls_any=frozenset({"call", "run", "Popen", "check_output", "check_call"}),
        imports_any=frozenset({"subprocess"}),
    ),
    SecurityRule(
        id="SEC-005",
        name="innerHTML assignment",
        severity="high",
        confidence="high",
        description="innerHTML allows injection of arbitrary HTML and script content",
        remediation="Use textContent for plain text or a sanitization library (DOMPurify)",
        owasp=["A03:2021"],
        cwe=["CWE-79"],
        languages=["javascript", "typescript"],
        calls_any=frozenset({"innerHTML"}),
        imports_any=frozenset(),
    ),
    SecurityRule(
        id="SEC-006",
        name="document.write usage",
        severity="medium",
        confidence="low",
        description="document.write can inject unsanitized content into the DOM",
        remediation="Use DOM APIs (createElement, textContent) instead of document.write",
        owasp=["A03:2021"],
        cwe=["CWE-79"],
        languages=["javascript", "typescript"],
        calls_any=frozenset({"write"}),
        imports_any=frozenset(),
    ),
    SecurityRule(
        id="SEC-007",
        name="dangerouslySetInnerHTML",
        severity="high",
        confidence="high",
        description="dangerouslySetInnerHTML bypasses React XSS protections",
        remediation="Sanitize HTML with DOMPurify before passing to dangerouslySetInnerHTML",
        owasp=["A03:2021"],
        cwe=["CWE-79"],
        languages=["javascript", "typescript"],
        calls_any=frozenset({"dangerouslySetInnerHTML"}),
        imports_any=frozenset(),
    ),
    SecurityRule(
        id="SEC-008",
        name="MD5 hash usage",
        severity="medium",
        confidence="medium",
        description="MD5 is cryptographically broken; collisions are trivially producible",
        remediation="Use SHA-256 or stronger (hashlib.sha256, hashlib.sha3_256)",
        owasp=["A02:2021"],
        cwe=["CWE-328"],
        languages=["python"],
        calls_any=frozenset({"md5", "MD5"}),
        imports_any=frozenset({"hashlib", "Crypto", "cryptography"}),
    ),
    SecurityRule(
        id="SEC-009",
        name="SHA1 hash usage",
        severity="medium",
        confidence="medium",
        description="SHA-1 is deprecated; collision attacks are practical",
        remediation="Use SHA-256 or stronger (hashlib.sha256, hashlib.sha3_256)",
        owasp=["A02:2021"],
        cwe=["CWE-328"],
        languages=["python"],
        calls_any=frozenset({"sha1", "SHA1"}),
        imports_any=frozenset({"hashlib", "Crypto"}),
    ),
    SecurityRule(
        id="SEC-010",
        name="pickle deserialization",
        severity="critical",
        confidence="high",
        description="pickle.load/loads deserializes arbitrary Python objects, enabling RCE",
        remediation="Use JSON or msgpack for data interchange; never unpickle untrusted data",
        owasp=["A08:2021"],
        cwe=["CWE-502"],
        languages=["python"],
        calls_any=frozenset({"load", "loads"}),
        imports_any=frozenset({"pickle", "cPickle"}),
    ),
    SecurityRule(
        id="SEC-011",
        name="yaml.load without SafeLoader",
        severity="high",
        confidence="medium",
        description="yaml.load() with default Loader can run arbitrary Python code",
        remediation="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
        owasp=["A08:2021"],
        cwe=["CWE-502"],
        languages=["python"],
        calls_any=frozenset({"load"}),
        imports_any=frozenset({"yaml"}),
    ),
    SecurityRule(
        id="SEC-012",
        name="marshal.loads deserialization",
        severity="high",
        confidence="high",
        description="marshal.loads can run arbitrary code during deserialization",
        remediation="Use JSON or msgpack; marshal is for .pyc internals, not data interchange",
        owasp=["A08:2021"],
        cwe=["CWE-502"],
        languages=["python"],
        calls_any=frozenset({"loads"}),
        imports_any=frozenset({"marshal"}),
    ),
    SecurityRule(
        id="SEC-013",
        name="tempfile.mktemp race condition",
        severity="medium",
        confidence="high",
        description="mktemp() creates a name without atomically creating the file (TOCTOU race)",
        remediation="Use tempfile.mkstemp() or tempfile.NamedTemporaryFile()",
        owasp=[],
        cwe=["CWE-377"],
        languages=["python"],
        calls_any=frozenset({"mktemp"}),
        imports_any=frozenset({"tempfile"}),
    ),
    SecurityRule(
        id="SEC-014",
        name="XML parsing (XXE risk)",
        severity="medium",
        confidence="medium",
        description="XML parsers may be vulnerable to XXE (external entity) attacks by default",
        remediation="Use defusedxml or disable external entity resolution explicitly",
        owasp=[],
        cwe=["CWE-611"],
        languages=["python"],
        calls_any=frozenset({"parse", "fromstring"}),
        imports_any=frozenset({"xml", "lxml", "etree"}),
    ),
    SecurityRule(
        id="SEC-015",
        name="HTTP client usage (SSRF risk)",
        severity="medium",
        confidence="low",
        description="HTTP client calls may be vulnerable to SSRF if URLs come from user input",
        remediation="Validate and allowlist URLs; block internal/private IP ranges",
        owasp=["A10:2021"],
        cwe=["CWE-918"],
        languages=["python"],
        calls_any=frozenset({"get", "post", "put", "delete", "request", "urlopen"}),
        imports_any=frozenset({"requests", "httpx", "urllib"}),
    ),
    SecurityRule(
        id="SEC-016",
        name="subprocess shell=True",
        severity="critical",
        confidence="high",
        description="subprocess call with shell=True runs commands through the shell, enabling injection",
        remediation="Use shell=False (default) and pass command as a list",
        owasp=["A03:2021"],
        cwe=["CWE-78"],
        languages=["python"],
        calls_any=frozenset({"call", "run", "Popen", "check_output", "check_call"}),
        imports_any=frozenset({"subprocess"}),
        arg_checker=_check_shell_true,
        supersedes="SEC-004",
    ),
    SecurityRule(
        id="SEC-017",
        name="yaml.load without SafeLoader",
        severity="high",
        confidence="high",
        description="yaml.load() without SafeLoader can execute arbitrary Python code",
        remediation="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
        owasp=["A08:2021"],
        cwe=["CWE-502"],
        languages=["python"],
        calls_any=frozenset({"load"}),
        imports_any=frozenset({"yaml"}),
        arg_checker=_check_yaml_unsafe_loader,
        supersedes="SEC-011",
    ),
    SecurityRule(
        id="SEC-018",
        name="bind to all interfaces",
        severity="medium",
        confidence="high",
        description="Binding to 0.0.0.0 exposes the service on all network interfaces",
        remediation="Bind to 127.0.0.1 for local-only access, or use a specific interface address",
        owasp=["A05:2021"],
        cwe=["CWE-668"],
        languages=["python"],
        calls_any=frozenset({"bind", "run", "run_simple"}),
        imports_any=frozenset({"socket", "flask", "werkzeug"}),
        arg_checker=_check_bind_all_interfaces,
    ),
    SecurityRule(
        id="SEC-019",
        name="debug mode enabled",
        severity="medium",
        confidence="high",
        description="Debug mode exposes stack traces, enables code execution, and leaks internal state",
        remediation="Set debug=False in production; use environment variables to control debug mode",
        owasp=["A05:2021"],
        cwe=["CWE-215"],
        languages=["python"],
        calls_any=frozenset({"run", "run_simple"}),
        imports_any=frozenset({"flask", "werkzeug"}),
        arg_checker=_check_debug_true,
    ),
]


# ---------------------------------------------------------------------------
# Module-level rules (assignment-only detection)
# ---------------------------------------------------------------------------

MODULE_LEVEL_RULES: list[ModuleLevelRule] = [
    ModuleLevelRule(
        id="SEC-020",
        name="DEBUG=True in settings",
        severity="medium",
        confidence="medium",
        description="DEBUG=True in module-level code exposes stack traces and enables code execution",
        remediation="Set DEBUG=False in production; use environment variables",
        owasp=["A05:2021"],
        cwe=["CWE-215"],
        target_name="DEBUG",
        dangerous_value="True",
    ),
    ModuleLevelRule(
        id="SEC-021",
        name="Hardcoded SECRET_KEY",
        severity="high",
        confidence="medium",
        description="Hardcoded SECRET_KEY at module level — secrets should come from environment variables",
        remediation="Use os.environ.get('SECRET_KEY') or a secrets manager",
        owasp=["A02:2021"],
        cwe=["CWE-798"],
        target_name="SECRET_KEY",
        dangerous_value=None,  # Any non-empty string literal
    ),
]


# ---------------------------------------------------------------------------
# Module-level scan engine
# ---------------------------------------------------------------------------


def _matches_module_category(rule: ModuleLevelRule, category: str) -> bool:
    """Check if a module-level rule matches a category filter."""
    cat_lower = category.lower()

    if cat_lower.startswith("owasp-"):
        prefix = cat_lower[len("owasp-"):].upper()
        return any(prefix in entry for entry in rule.owasp)

    if cat_lower.startswith("cwe-"):
        prefix = cat_lower[len("cwe-"):].upper()
        return any(prefix in entry.upper() for entry in rule.cwe)

    return any(cat_lower in entry.lower() for entry in rule.owasp + rule.cwe)


def scan_module_level(
    file_sources: dict[str, bytes] | None,
    module_rules: list[ModuleLevelRule] | None = None,
    category: str | None = None,
    min_severity: str | None = None,
) -> list[dict]:
    """Scan module-level assignments for dangerous patterns.

    Args:
        file_sources: Mapping of file paths to raw source bytes (Python files).
        module_rules: Rule set to apply. Defaults to MODULE_LEVEL_RULES.
        category: Optional category filter (e.g. "owasp-a05", "cwe-215").
        min_severity: Optional minimum severity threshold.

    Returns:
        List of finding dicts, sorted by severity then file/line/rule_id.
    """
    if not file_sources:
        return []

    if module_rules is None:
        module_rules = MODULE_LEVEL_RULES

    active_rules = module_rules
    if category:
        active_rules = [r for r in active_rules if _matches_module_category(r, category)]
    if min_severity:
        min_order = _SEVERITY_ORDER.get(min_severity.lower(), 3)
        active_rules = [
            r for r in active_rules
            if _SEVERITY_ORDER.get(r.severity, 3) <= min_order
        ]

    if not active_rules:
        return []

    try:
        from tree_sitter_language_pack import get_parser
    except ImportError:
        return []

    try:
        parser = get_parser("python")
    except (KeyError, ValueError):
        return []

    # Node types to skip (not module-level assignments)
    _SKIP_TYPES = {"function_definition", "class_definition", "decorated_definition"}

    findings: list[dict] = []

    for file_path, source_bytes in file_sources.items():
        tree = parser.parse(source_bytes)
        if tree is None or tree.root_node is None:
            continue

        for child in tree.root_node.children:
            if child.type in _SKIP_TYPES:
                continue

            # Find assignment nodes: either direct or wrapped in expression_statement
            assignment_node = None
            if child.type == "assignment":
                assignment_node = child
            elif child.type == "expression_statement":
                for sub in child.children:
                    if sub.type == "assignment":
                        assignment_node = sub
                        break

            if assignment_node is None:
                continue

            # Extract target name from left side
            left = assignment_node.child_by_field_name("left")
            if left is None:
                continue

            # Get the identifier text from the left side
            if left.type == "identifier":
                target_text = left.text.decode("utf-8", errors="replace")
            else:
                # Could be pattern_list, tuple, etc. — skip complex targets
                continue

            # Extract value from right side
            right = assignment_node.child_by_field_name("right")
            if right is None:
                continue

            value_text = right.text.decode("utf-8", errors="replace")
            value_type = right.type

            for rule in active_rules:
                if target_text != rule.target_name:
                    continue

                if rule.dangerous_value is not None:
                    # Exact match on the value text
                    if value_text != rule.dangerous_value:
                        continue
                else:
                    # Any non-empty, non-f-string string literal
                    if value_type != "string":
                        continue
                    # Exclude f-strings (contain interpolation)
                    if value_text.startswith(("f\"", "f'", "F\"", "F'")):
                        continue
                    # Exclude empty strings ("" or '')
                    if len(value_text) <= 2:
                        continue

                findings.append({
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "severity": rule.severity,
                    "confidence": rule.confidence,
                    "description": rule.description,
                    "remediation": rule.remediation,
                    "owasp": list(rule.owasp),
                    "cwe": list(rule.cwe),
                    "symbol": "(module-level)",
                    "file": file_path,
                    "line": assignment_node.start_point[0] + 1,
                    "matched_calls": [],
                })

    # Deterministic sort: severity, file, line, rule_id
    findings.sort(key=lambda f: (
        _SEVERITY_ORDER.get(f["severity"], 3),
        f.get("file", ""),
        f.get("line", 0),
        f["rule_id"],
    ))

    return findings


# ---------------------------------------------------------------------------
# Scan engine
# ---------------------------------------------------------------------------


def _matches_category(rule: SecurityRule, category: str) -> bool:
    """Check if rule matches a category filter (case-insensitive prefix).

    Examples: "owasp-a03" matches rule with "A03:2021",
              "cwe-94" matches rule with "CWE-94".
    """
    cat_lower = category.lower()

    if cat_lower.startswith("owasp-"):
        prefix = cat_lower[len("owasp-"):].upper()
        return any(prefix in entry for entry in rule.owasp)

    if cat_lower.startswith("cwe-"):
        prefix = cat_lower[len("cwe-"):].upper()
        return any(prefix in entry.upper() for entry in rule.cwe)

    # Fallback: check if category appears anywhere in owasp or cwe lists
    return any(cat_lower in entry.lower() for entry in rule.owasp + rule.cwe)


def scan_symbols(
    symbols: list[dict],
    rules: list[SecurityRule] | None = None,
    category: str | None = None,
    min_severity: str | None = None,
    limit: int = 100,
    symbol_sources: dict[str, bytes] | None = None,
) -> tuple[list[dict], int, bool]:
    """Scan symbols for security hotspots.

    Args:
        symbols: List of symbol dicts from the index (must have calls, imports,
                 file, line, language, name keys).
        rules: Rule set to apply. Defaults to RULES.
        category: Optional category filter (e.g. "owasp-a03", "cwe-94").
        min_severity: Optional minimum severity threshold.
        limit: Maximum findings to return (capped at 500).
        symbol_sources: Optional mapping of "file:line:name" keys to source bytes
                        for argument-sensitive rule checking.

    Returns:
        Tuple of (findings_list, total_count, was_truncated).
    """
    if rules is None:
        rules = RULES

    # Filter rules by category
    active_rules = rules
    if category:
        active_rules = [r for r in active_rules if _matches_category(r, category)]

    # Filter rules by minimum severity
    if min_severity:
        min_order = _SEVERITY_ORDER.get(min_severity.lower(), 3)
        active_rules = [
            r for r in active_rules
            if _SEVERITY_ORDER.get(r.severity, 3) <= min_order
        ]

    if not active_rules:
        return [], 0, False

    # Build file-level imports map for nested symbol fallback
    file_imports: dict[str, set[str]] = {}
    for sym in symbols:
        for imp in sym.get("imports", []):
            file_imports.setdefault(sym.get("file", ""), set()).add(imp)

    all_findings: list[dict] = []
    # Track per-symbol suppressed rule IDs from arg-checker supersedes
    suppressed: dict[str, set[str]] = {}

    for sym in symbols:
        sym_calls = set(sym.get("calls", []))
        if not sym_calls:
            continue

        sym_imports = set(sym.get("imports", []))
        sym_file = sym.get("file", "")
        sym_language = sym.get("language", "").lower()
        sym_key = f"{sym_file}:{sym.get('line', 0)}:{sym.get('name', '')}"

        # Fallback: use file-level imports when symbol has none
        effective_imports = sym_imports if sym_imports else file_imports.get(sym_file, set())

        for rule in active_rules:
            # Language check
            if "*" not in rule.languages and sym_language not in rule.languages:
                continue

            # Calls check: at least one call must match
            if not sym_calls & rule.calls_any:
                continue

            # Import check (only for import-assisted rules)
            if rule.imports_any and not effective_imports & rule.imports_any:
                continue

            matched_calls = sorted(sym_calls & rule.calls_any)

            # Argument-sensitive checking
            if rule.arg_checker is not None:
                if symbol_sources is None or sym_key not in symbol_sources:
                    # No source available: skip arg-sensitive rule entirely
                    continue
                source_bytes = symbol_sources[sym_key]
                checker_ok, is_dangerous = _parse_and_check_args(
                    source_bytes, sym_language, rule.arg_checker,
                )
                if not checker_ok:
                    # Parse/checker failed: skip, don't suppress fallback
                    continue
                # Checker succeeded: record supersession regardless of danger
                if rule.supersedes:
                    suppressed.setdefault(sym_key, set()).add(rule.supersedes)
                if not is_dangerous:
                    continue

            finding = {
                "rule_id": rule.id,
                "rule_name": rule.name,
                "severity": rule.severity,
                "confidence": rule.confidence,
                "description": rule.description,
                "remediation": rule.remediation,
                "owasp": list(rule.owasp),
                "cwe": list(rule.cwe),
                "symbol": sym.get("name", ""),
                "file": sym_file,
                "line": sym.get("line", 0),
                "matched_calls": matched_calls,
            }
            all_findings.append(finding)

    # Filter out findings suppressed by arg-checker supersedes
    if suppressed:
        all_findings = [
            f for f in all_findings
            if f["rule_id"] not in suppressed.get(
                f"{f['file']}:{f['line']}:{f['symbol']}", set(),
            )
        ]

    # Sort by severity order (critical first)
    all_findings.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 3))

    total = len(all_findings)
    truncated = total > limit
    return all_findings[:limit], total, truncated
