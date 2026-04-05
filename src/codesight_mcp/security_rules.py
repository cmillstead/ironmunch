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
]


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
) -> tuple[list[dict], int, bool]:
    """Scan symbols for security hotspots.

    Args:
        symbols: List of symbol dicts from the index (must have calls, imports,
                 file, line, language, name keys).
        rules: Rule set to apply. Defaults to RULES.
        category: Optional category filter (e.g. "owasp-a03", "cwe-94").
        min_severity: Optional minimum severity threshold.
        limit: Maximum findings to return (capped at 500).

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

    for sym in symbols:
        sym_calls = set(sym.get("calls", []))
        if not sym_calls:
            continue

        sym_imports = set(sym.get("imports", []))
        sym_file = sym.get("file", "")
        sym_language = sym.get("language", "").lower()

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

    # Sort by severity order (critical first)
    all_findings.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 3))

    total = len(all_findings)
    truncated = total > limit
    return all_findings[:limit], total, truncated
