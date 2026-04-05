"""Tests for security rule engine and scan_security tool.

Tier 1: Unit tests for scan_symbols with mock symbol dicts.
Tier 2: End-to-end integration tests with real parsed code.
"""


from codesight_mcp.security_rules import RULES, scan_symbols


# ===========================================================================
# Tier 1: Unit tests -- per-rule detection with actual data shape
# ===========================================================================


def _make_symbol(
    name: str = "func",
    calls: list[str] | None = None,
    imports: list[str] | None = None,
    language: str = "python",
    file: str = "test.py",
    line: int = 1,
    parent: str | None = None,
) -> dict:
    """Build a symbol dict matching the shape produced by the extractor."""
    return {
        "name": name,
        "calls": calls or [],
        "imports": imports or [],
        "language": language,
        "file": file,
        "line": line,
        "parent": parent,
    }


class TestEvalDetection:
    """SEC-001: eval() usage -- calls-only rule, all languages."""

    def test_eval_detected(self):
        symbols = [_make_symbol(calls=["eval"], imports=[])]
        findings, total, _ = scan_symbols(symbols)
        assert total >= 1
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-001" in rule_ids

    def test_eval_severity_critical(self):
        symbols = [_make_symbol(calls=["eval"])]
        findings, _, _ = scan_symbols(symbols)
        eval_finding = next(f for f in findings if f["rule_id"] == "SEC-001")
        assert eval_finding["severity"] == "critical"


class TestExecDetection:
    """SEC-002: exec() usage."""

    def test_exec_detected(self):
        symbols = [_make_symbol(calls=["exec"], imports=[])]
        findings, total, _ = scan_symbols(symbols)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-002" in rule_ids


class TestOsSystemDetection:
    """SEC-003: os.system/popen -- import-assisted rule."""

    def test_os_system_import_assisted(self):
        symbols = [_make_symbol(calls=["system"], imports=["os"])]
        findings, total, _ = scan_symbols(symbols)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-003" in rule_ids

    def test_os_system_no_import_no_match(self):
        symbols = [_make_symbol(calls=["system"], imports=[])]
        findings, total, _ = scan_symbols(symbols)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-003" not in rule_ids


class TestPickleDetection:
    """SEC-010: pickle deserialization."""

    def test_pickle_load_import_assisted(self):
        symbols = [_make_symbol(calls=["load"], imports=["pickle"])]
        findings, total, _ = scan_symbols(symbols)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-010" in rule_ids

    def test_pickle_no_pickle_import(self):
        symbols = [_make_symbol(calls=["load"], imports=["json"])]
        findings, total, _ = scan_symbols(symbols)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-010" not in rule_ids


class TestMd5Detection:
    """SEC-008: MD5 hash usage."""

    def test_md5_import_assisted(self):
        symbols = [_make_symbol(calls=["md5"], imports=["hashlib"])]
        findings, total, _ = scan_symbols(symbols)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-008" in rule_ids


class TestSubprocessDetection:
    """SEC-004: subprocess usage."""

    def test_subprocess_import_assisted(self):
        symbols = [_make_symbol(calls=["call"], imports=["subprocess"])]
        findings, total, _ = scan_symbols(symbols)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-004" in rule_ids


class TestTempfileMktemp:
    """SEC-013: tempfile.mktemp race condition."""

    def test_tempfile_mktemp(self):
        symbols = [_make_symbol(calls=["mktemp"], imports=["tempfile"])]
        findings, total, _ = scan_symbols(symbols)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-013" in rule_ids


class TestSafeCode:
    """Safe code should produce zero findings."""

    def test_safe_code_no_findings(self):
        symbols = [_make_symbol(calls=["print", "len"], imports=["os"])]
        findings, total, _ = scan_symbols(symbols)
        assert total == 0


class TestJavaScriptRules:
    """SEC-005: innerHTML -- language-specific rule."""

    def test_js_innerhtml(self):
        symbols = [_make_symbol(calls=["innerHTML"], language="javascript")]
        findings, total, _ = scan_symbols(symbols)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-005" in rule_ids

    def test_js_rule_not_on_python(self):
        symbols = [_make_symbol(calls=["innerHTML"], language="python")]
        findings, total, _ = scan_symbols(symbols)
        assert total == 0


class TestNestedSymbolImportFallback:
    """File-level import fallback for nested symbols (methods)."""

    def test_nested_symbol_import_fallback(self):
        top_level = _make_symbol(
            name="module_top",
            calls=[],
            imports=["os"],
            file="runner.py",
        )
        method = _make_symbol(
            name="execute",
            calls=["system"],
            imports=[],
            file="runner.py",
            parent="Runner",
        )
        findings, total, _ = scan_symbols([top_level, method])
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-003" in rule_ids
        method_findings = [f for f in findings if f["symbol"] == "execute"]
        assert len(method_findings) > 0


# ===========================================================================
# Tier 1: Filter and output tests
# ===========================================================================


class TestCategoryFilter:
    """Category filters narrow rules to OWASP or CWE subsets."""

    def test_category_filter_owasp(self):
        symbols = [_make_symbol(calls=["eval", "system"], imports=["os"])]
        findings, _, _ = scan_symbols(symbols, category="owasp-a03")
        rule_ids = {f["rule_id"] for f in findings}
        # All returned findings should be from A03 rules
        a03_rule_ids = {r.id for r in RULES if any("A03" in e for e in r.owasp)}
        assert rule_ids <= a03_rule_ids

    def test_category_filter_cwe(self):
        symbols = [_make_symbol(calls=["eval"])]
        findings, _, _ = scan_symbols(symbols, category="cwe-94")
        rule_ids = {f["rule_id"] for f in findings}
        cwe94_rule_ids = {r.id for r in RULES if any("94" in e for e in r.cwe)}
        assert rule_ids <= cwe94_rule_ids
        assert len(findings) > 0


class TestSeverityFilter:
    """Min severity threshold excludes lower-severity findings."""

    def test_severity_filter_high(self):
        symbols = [
            _make_symbol(calls=["eval"]),       # critical
            _make_symbol(calls=["md5"], imports=["hashlib"]),  # medium
        ]
        findings, _, _ = scan_symbols(symbols, min_severity="high")
        severities = {f["severity"] for f in findings}
        assert "medium" not in severities
        assert "low" not in severities

    def test_severity_filter_critical(self):
        symbols = [
            _make_symbol(calls=["eval"]),       # critical
            _make_symbol(calls=["innerHTML"], language="javascript"),  # high
            _make_symbol(calls=["md5"], imports=["hashlib"]),  # medium
        ]
        findings, _, _ = scan_symbols(symbols, min_severity="critical")
        severities = {f["severity"] for f in findings}
        assert severities == {"critical"}


class TestOutputLimit:
    """Limit caps returned findings, reports total and truncated flag."""

    def test_output_limit(self):
        # Create many symbols that each trigger eval (SEC-001)
        symbols = [
            _make_symbol(name=f"func_{i}", calls=["eval"])
            for i in range(20)
        ]
        findings, total, truncated = scan_symbols(symbols, limit=5)
        assert len(findings) == 5
        assert total == 20
        assert truncated is True


class TestMultipleFindings:
    """Single symbol can trigger multiple rules."""

    def test_multiple_findings(self):
        symbols = [_make_symbol(calls=["eval", "load"], imports=["pickle"])]
        findings, total, _ = scan_symbols(symbols)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-001" in rule_ids   # eval
        assert "SEC-010" in rule_ids   # pickle.load
        assert total >= 2


class TestFindingsSorted:
    """Findings sorted by severity: critical -> high -> medium -> low."""

    def test_findings_sorted(self):
        symbols = [
            _make_symbol(calls=["eval"]),       # critical
            _make_symbol(calls=["md5"], imports=["hashlib"]),  # medium
            _make_symbol(calls=["innerHTML"], language="javascript"),  # high
        ]
        findings, _, _ = scan_symbols(symbols)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        orders = [severity_order[f["severity"]] for f in findings]
        assert orders == sorted(orders)


class TestRuleSetIntegrity:
    """RULES list has expected structure and coverage."""

    def test_rule_count(self):
        assert len(RULES) >= 15

    def test_all_rules_have_tags(self):
        for rule in RULES:
            has_tag = len(rule.owasp) > 0 or len(rule.cwe) > 0
            assert has_tag, f"Rule {rule.id} has no owasp or cwe tags"

    def test_all_rules_have_confidence(self):
        valid_confidence = {"high", "medium", "low"}
        for rule in RULES:
            assert rule.confidence in valid_confidence, (
                f"Rule {rule.id} has invalid confidence: {rule.confidence}"
            )


# ===========================================================================
# Tier 2: End-to-end with REAL parsed code
# ===========================================================================


class TestScanE2EPython:
    """Index real Python with dangerous calls, verify detection."""

    def test_scan_e2e_python(self, tmp_path):
        from codesight_mcp.parser.extractor import parse_file
        from dataclasses import asdict

        code = '''import os
import pickle

def run_command(cmd):
    os.system(cmd)

def load_data(path):
    with open(path, 'rb') as f:
        return pickle.load(f)

def safe_function():
    return len([1, 2, 3])
'''
        symbols = parse_file(code, "vuln.py", "python")
        # Verify actual calls format first
        run_cmd = [s for s in symbols if s.name == "run_command"][0]
        assert "system" in run_cmd.calls, (
            f"Expected bare name system, got {run_cmd.calls}"
        )

        sym_dicts = [asdict(s) for s in symbols]
        findings, total, _ = scan_symbols(sym_dicts)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-003" in rule_ids, f"os.system not detected: {rule_ids}"
        assert "SEC-010" in rule_ids, f"pickle.load not detected: {rule_ids}"
        # safe_function should have no findings
        safe = [f for f in findings if f.get("symbol") == "safe_function"]
        assert len(safe) == 0

    def test_scan_e2e_nested_method(self, tmp_path):
        """Class method with dangerous call -- imports are on file level only."""
        from codesight_mcp.parser.extractor import parse_file
        from dataclasses import asdict

        code = '''import os

class Runner:
    def execute(self, cmd):
        os.system(cmd)
'''
        symbols = parse_file(code, "runner.py", "python")
        sym_dicts = [asdict(s) for s in symbols]
        findings, _, _ = scan_symbols(sym_dicts)
        # The method should be detected via file_imports fallback
        method_findings = [
            f for f in findings if "execute" in f.get("symbol", "")
        ]
        assert len(method_findings) > 0, (
            f"Nested method not detected. All findings: {findings}"
        )


class TestScanE2EJavaScript:
    """Index real JavaScript, verify detection via parser+scanner pipeline.

    Note: tree-sitter extracts function calls but not property assignments
    like innerHTML. The unit tests (TestJavaScriptRules) verify the rule
    engine detects innerHTML when present in calls. This E2E test uses
    document.write which IS extracted as a real call by the parser.
    """

    def test_scan_e2e_js(self, tmp_path):
        from codesight_mcp.parser.extractor import parse_file
        from dataclasses import asdict

        # document.write is a real function call that tree-sitter extracts
        code = "function renderContent(html) {\n    document.write(html);\n}\n"
        symbols = parse_file(code, "render.js", "javascript")
        sym_dicts = [asdict(s) for s in symbols]
        findings, total, _ = scan_symbols(sym_dicts)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-006" in rule_ids, f"document.write not detected: {rule_ids}"


class TestScanNoFindingsE2E:
    """Clean code should produce zero findings."""

    def test_scan_no_findings_e2e(self, tmp_path):
        from codesight_mcp.parser.extractor import parse_file
        from dataclasses import asdict

        code = '''def add(a, b):
    return a + b

def greet(name):
    return f"Hello, {name}"
'''
        symbols = parse_file(code, "clean.py", "python")
        sym_dicts = [asdict(s) for s in symbols]
        findings, total, _ = scan_symbols(sym_dicts)
        assert total == 0, (
            f"Expected 0 findings for clean code, got {total}: {findings}"
        )


# ===========================================================================
# Registry test
# ===========================================================================


class TestToolRegistered:
    """scan_security tool is registered with correct flags."""

    def test_tool_registered(self):
        import codesight_mcp.tools.scan_security  # noqa: F401 -- trigger registration
        from codesight_mcp.tools.registry import get_all_specs

        specs = get_all_specs()
        assert "scan_security" in specs, "scan_security not in registry"
        spec = specs["scan_security"]
        assert spec.untrusted is True
        assert spec.annotations is not None
        assert spec.annotations.readOnlyHint is True
