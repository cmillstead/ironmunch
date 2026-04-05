"""Scan indexed symbols for dangerous API usage patterns."""

import errno
import os
from typing import Optional

from mcp.types import ToolAnnotations

from ..core.boundaries import make_meta, wrap_untrusted_content
from ..security_rules import (
    MODULE_LEVEL_RULES,
    RULES,
    _SEVERITY_ORDER,
    _matches_module_category,
    scan_module_level,
    scan_symbols,
)
from ._common import RepoContext, timed, elapsed_ms
from .registry import ToolSpec, register


def scan_security(
    repo: str,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
    storage_path: Optional[str] = None,
) -> dict:
    """Scan indexed symbols for dangerous API usage patterns.

    Args:
        repo: Repository identifier (owner/repo or just repo name).
        category: Optional category filter (e.g. "owasp-a03", "cwe-94").
        severity: Optional minimum severity threshold (critical, high, medium, low).
        limit: Maximum findings to return (1-500, default 100).
        storage_path: Custom storage path.

    Returns:
        Dict with scan_summary, findings, limitations, and _meta envelope.
    """
    start = timed()

    # Validate severity
    if severity and severity.lower() not in _SEVERITY_ORDER:
        return {
            "error": (
                f"Invalid severity: {severity!r}. "
                f"Must be one of: critical, high, medium, low"
            ),
        }

    # Clamp limit to 1-100 (server._sanitize_arguments caps limit at 100)
    limit = max(1, min(100, limit))

    ctx = RepoContext.resolve(repo, storage_path)
    if isinstance(ctx, dict):
        return ctx
    owner, name, index = ctx.owner, ctx.name, ctx.index

    symbols = index.symbols

    # Build symbol_sources for argument-sensitive rules
    symbol_sources: dict[str, bytes] | None = None
    try:
        symbol_sources = {}
        for sym in symbols:
            sym_id = sym.get("id")
            if sym_id:
                content = ctx.store.get_symbol_content(
                    owner, name, sym_id, index=ctx.index,
                )
                if content is not None:
                    sym_key = f"{sym.get('file', '')}:{sym.get('line', 0)}:{sym.get('name', '')}"
                    symbol_sources[sym_key] = content.encode("utf-8")
        if not symbol_sources:
            symbol_sources = None
    except Exception:  # noqa: BLE001
        symbol_sources = None  # Graceful degradation

    # Build file_sources for module-level scanning (Python files only)
    from ..core.validation import ValidationError, validate_path

    file_sources: dict[str, bytes] | None = None
    try:
        content_dir = ctx.store._content_dir(owner, name)
        file_sources = {}
        for source_file in index.source_files:
            if not source_file.endswith(".py"):
                continue
            try:
                validated = validate_path(source_file, str(content_dir))
            except ValidationError:
                continue
            try:
                fd = os.open(str(validated), os.O_RDONLY | os.O_NOFOLLOW)
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOENT):
                    continue
                continue
            try:
                with os.fdopen(fd, "rb") as f:
                    file_sources[source_file] = f.read()
            except OSError:
                continue
        if not file_sources:
            file_sources = None
    except Exception:  # noqa: BLE001
        file_sources = None

    # Get ALL findings first (large limit) for accurate severity counts
    all_findings, total, _ = scan_symbols(
        symbols,
        rules=RULES,
        category=category,
        min_severity=severity,
        limit=10000,  # Get all for accurate counts
        symbol_sources=symbol_sources,
    )

    # Module-level scanning for assignment patterns
    module_findings = scan_module_level(file_sources, MODULE_LEVEL_RULES, category, severity)
    all_findings.extend(module_findings)

    # Re-sort merged findings by severity, file, line, rule_id
    all_findings.sort(key=lambda f: (
        _SEVERITY_ORDER.get(f["severity"], 3),
        f.get("file", ""),
        f.get("line", 0),
        f["rule_id"],
    ))
    total = len(all_findings)
    truncated = total > limit
    findings = all_findings[:limit]

    # Count active rules (after category/severity filtering)
    active_rules = RULES
    if category:
        from ..security_rules import _matches_category
        active_rules = [r for r in active_rules if _matches_category(r, category)]
    if severity:
        min_order = _SEVERITY_ORDER.get(severity.lower(), 3)
        active_rules = [
            r for r in active_rules
            if _SEVERITY_ORDER.get(r.severity, 3) <= min_order
        ]

    # Count active module-level rules
    active_module_rules = MODULE_LEVEL_RULES
    if category:
        active_module_rules = [
            r for r in active_module_rules if _matches_module_category(r, category)
        ]
    if severity:
        min_order = _SEVERITY_ORDER.get(severity.lower(), 3)
        active_module_rules = [
            r for r in active_module_rules
            if _SEVERITY_ORDER.get(r.severity, 3) <= min_order
        ]

    # Build severity breakdown from ALL findings, not just returned slice
    by_severity: dict[str, int] = {}
    for finding in all_findings:
        sev = finding["severity"]
        by_severity[sev] = by_severity.get(sev, 0) + 1

    # Wrap untrusted string fields in findings
    wrapped_findings = []
    for finding in findings:
        wrapped = dict(finding)
        wrapped["symbol"] = wrap_untrusted_content(str(finding["symbol"]))
        wrapped["file"] = wrap_untrusted_content(str(finding["file"]))
        wrapped["description"] = wrap_untrusted_content(str(finding["description"]))
        wrapped["remediation"] = wrap_untrusted_content(str(finding["remediation"]))
        wrapped["rule_name"] = wrap_untrusted_content(str(finding["rule_name"]))
        wrapped["matched_calls"] = [
            wrap_untrusted_content(c) for c in finding["matched_calls"]
        ]
        wrapped_findings.append(wrapped)

    # Collect all available categories from full rule set
    all_categories: set[str] = set()
    for rule in RULES:
        for entry in rule.owasp:
            all_categories.add(f"owasp-{entry.split(':')[0].lower()}")
        for entry in rule.cwe:
            all_categories.add(entry.lower())
    for rule in MODULE_LEVEL_RULES:
        for entry in rule.owasp:
            all_categories.add(f"owasp-{entry.split(':')[0].lower()}")
        for entry in rule.cwe:
            all_categories.add(entry.lower())

    ms = elapsed_ms(start)

    return {
        "repo": f"{owner}/{name}",
        "scan_type": "dangerous_api_usage",
        "scan_summary": {
            "symbols_scanned": len(symbols),
            "rules_applied": len(active_rules) + len(active_module_rules),
            "findings_total": total,
            "findings_returned": len(wrapped_findings),
            "truncated": truncated,
            "by_severity": by_severity,
        },
        "findings": wrapped_findings,
        "limitations": [
            "Module-level scanning detects dangerous assignments (DEBUG, SECRET_KEY) in Python files; module-level call detection uses symbol-level scanning only",
            "Matches bare call names from index, not full qualified paths",
            "Argument inspection available for Python (shell=True, SafeLoader, bind, debug); other languages call-name only",
            "Findings are potential hotspots, not confirmed vulnerabilities",
        ],
        "categories_available": sorted(all_categories),
        "_meta": {
            **make_meta(source="security_scan", trusted=False),
            "timing_ms": ms,
        },
    }


_spec = register(ToolSpec(
    name="scan_security",
    description=(
        "Scan indexed symbols for dangerous API usage patterns. "
        "Detects eval/exec, command injection, XSS sinks, weak crypto, "
        "unsafe deserialization, and SSRF-prone HTTP calls. "
        "Returns findings with OWASP/CWE references and remediation guidance. "
        "WARNING: Results contain untrusted content from indexed source code."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "repo": {
                "type": "string",
                "description": "Repository identifier (owner/repo or just repo name)",
            },
            "category": {
                "type": "string",
                "description": (
                    "Filter by category (e.g. 'owasp-a03', 'cwe-94'). "
                    "Case-insensitive prefix match."
                ),
            },
            "severity": {
                "type": "string",
                "description": (
                    "Minimum severity threshold: critical, high, medium, or low"
                ),
            },
            "limit": {
                "type": "integer",
                "description": "Maximum findings to return (1-500, default 100)",
                "default": 100,
            },
        },
        "required": ["repo"],
    },
    handler=lambda args, storage_path: scan_security(
        repo=args["repo"],
        category=args.get("category"),
        severity=args.get("severity"),
        limit=args.get("limit", 100),
        storage_path=storage_path,
    ),
    required_args=["repo"],
    untrusted=True,
    annotations=ToolAnnotations(
        title="Scan Security",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
))
