"""Tests for scan_module_level and MODULE_LEVEL_RULES."""

from codesight_mcp.security_rules import scan_module_level


class TestDebugAssignment:
    """AC-1: DEBUG assignment detection."""

    def test_debug_true_at_root(self):
        source = b"DEBUG = True\n"
        findings = scan_module_level({"test.py": source})
        rule_ids = [f["rule_id"] for f in findings]
        assert "SEC-020" in rule_ids

    def test_debug_false_at_root(self):
        source = b"DEBUG = False\n"
        findings = scan_module_level({"test.py": source})
        rule_ids = [f["rule_id"] for f in findings]
        assert "SEC-020" not in rule_ids

    def test_debug_true_inside_function(self):
        source = b"def func():\n    DEBUG = True\n"
        findings = scan_module_level({"test.py": source})
        rule_ids = [f["rule_id"] for f in findings]
        assert "SEC-020" not in rule_ids


class TestSecretKeyAssignment:
    """AC-1: SECRET_KEY assignment detection."""

    def test_secret_key_hardcoded_string(self):
        source = b'SECRET_KEY = "mysecretvalue"\n'
        findings = scan_module_level({"test.py": source})
        rule_ids = [f["rule_id"] for f in findings]
        assert "SEC-021" in rule_ids

    def test_secret_key_empty_string(self):
        source = b'SECRET_KEY = ""\n'
        findings = scan_module_level({"test.py": source})
        rule_ids = [f["rule_id"] for f in findings]
        assert "SEC-021" not in rule_ids

    def test_secret_key_fstring(self):
        source = b'SECRET_KEY = f"{variable}"\n'
        findings = scan_module_level({"test.py": source})
        rule_ids = [f["rule_id"] for f in findings]
        assert "SEC-021" not in rule_ids

    def test_secret_key_environ_call(self):
        source = b'import os\nSECRET_KEY = os.environ.get("KEY")\n'
        findings = scan_module_level({"test.py": source})
        rule_ids = [f["rule_id"] for f in findings]
        assert "SEC-021" not in rule_ids

    def test_secret_key_none(self):
        source = b"SECRET_KEY = None\n"
        findings = scan_module_level({"test.py": source})
        rule_ids = [f["rule_id"] for f in findings]
        assert "SEC-021" not in rule_ids

    def test_secret_key_single_quotes(self):
        source = b"SECRET_KEY = 'mysecret'\n"
        findings = scan_module_level({"test.py": source})
        rule_ids = [f["rule_id"] for f in findings]
        assert "SEC-021" in rule_ids


class TestModuleLevelIntegration:
    """AC-2: Integration tests for scan_module_level."""

    def test_file_sources_none_returns_empty(self):
        findings = scan_module_level(None)
        assert findings == []

    def test_empty_file_sources(self):
        findings = scan_module_level({})
        assert findings == []

    def test_empty_file_content(self):
        findings = scan_module_level({"test.py": b""})
        assert findings == []

    def test_imports_only_file(self):
        source = b"import os\nimport sys\n"
        findings = scan_module_level({"test.py": source})
        assert findings == []

    def test_finding_has_module_level_symbol(self):
        source = b"DEBUG = True\n"
        findings = scan_module_level({"test.py": source})
        assert len(findings) >= 1
        assert findings[0]["symbol"] == "(module-level)"

    def test_finding_has_correct_file(self):
        source = b"DEBUG = True\n"
        findings = scan_module_level({"settings.py": source})
        matching = [f for f in findings if f["rule_id"] == "SEC-020"]
        assert len(matching) >= 1
        assert matching[0]["file"] == "settings.py"

    def test_category_filter_includes_module_rules(self):
        source = b"DEBUG = True\n"
        findings_match = scan_module_level({"test.py": source}, category="cwe-215")
        rule_ids_match = [f["rule_id"] for f in findings_match]
        assert "SEC-020" in rule_ids_match

        findings_no_match = scan_module_level({"test.py": source}, category="cwe-999")
        assert findings_no_match == []

    def test_severity_filter(self):
        source = b'DEBUG = True\nSECRET_KEY = "abc"\n'
        findings = scan_module_level({"test.py": source}, min_severity="high")
        rule_ids = [f["rule_id"] for f in findings]
        # SEC-021 is high severity, SEC-020 is medium
        assert "SEC-021" in rule_ids
        assert "SEC-020" not in rule_ids


class TestEdgeCases:
    """Edge case tests for module-level scanning."""

    def test_multiple_assignments_one_file(self):
        source = b'DEBUG = True\nSECRET_KEY = "abc"\n'
        findings = scan_module_level({"test.py": source})
        rule_ids = [f["rule_id"] for f in findings]
        assert "SEC-020" in rule_ids
        assert "SEC-021" in rule_ids

    def test_non_matching_assignment(self):
        source = b"FOO = True\n"
        findings = scan_module_level({"test.py": source})
        assert findings == []
