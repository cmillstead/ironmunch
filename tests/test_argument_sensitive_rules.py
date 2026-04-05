"""Tests for argument-sensitive security rules (SEC-016 through SEC-019).

Validates AST-based argument checking with real tree-sitter parsing.
No mocks -- source strings are real Python parsed by tree-sitter.
"""

from codesight_mcp.security_rules import scan_symbols


def _make_symbol(
    name: str = "func",
    calls: list[str] | None = None,
    imports: list[str] | None = None,
    language: str = "python",
    file: str = "test.py",
    line: int = 1,
) -> dict:
    """Build a symbol dict matching the shape produced by the extractor."""
    return {
        "name": name,
        "calls": calls or [],
        "imports": imports or [],
        "language": language,
        "file": file,
        "line": line,
    }


def _source_key(file: str = "test.py", line: int = 1, name: str = "func") -> str:
    return f"{file}:{line}:{name}"


# ---------------------------------------------------------------------------
# AC-1: SEC-016 -- subprocess shell=True
# ---------------------------------------------------------------------------


class TestShellTrue:
    """SEC-016: subprocess call with shell=True."""

    def test_shell_true_detected(self):
        sym = _make_symbol(calls=["run"], imports=["subprocess"])
        source = b"import subprocess\ndef func():\n    subprocess.run(cmd, shell=True)\n"
        sources = {_source_key(): source}
        findings, total, _ = scan_symbols([sym], symbol_sources=sources)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-016" in rule_ids

    def test_shell_false_not_detected(self):
        sym = _make_symbol(calls=["run"], imports=["subprocess"])
        source = b"import subprocess\ndef func():\n    subprocess.run(cmd, shell=False)\n"
        sources = {_source_key(): source}
        findings, total, _ = scan_symbols([sym], symbol_sources=sources)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-016" not in rule_ids

    def test_no_shell_kwarg_not_detected(self):
        sym = _make_symbol(calls=["run"], imports=["subprocess"])
        source = b"import subprocess\ndef func():\n    subprocess.run(cmd)\n"
        sources = {_source_key(): source}
        findings, total, _ = scan_symbols([sym], symbol_sources=sources)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-016" not in rule_ids

    def test_shell_true_suppresses_sec004(self):
        sym = _make_symbol(calls=["run"], imports=["subprocess"])
        source = b"import subprocess\ndef func():\n    subprocess.run(cmd, shell=True)\n"
        sources = {_source_key(): source}
        findings, total, _ = scan_symbols([sym], symbol_sources=sources)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-016" in rule_ids
        assert "SEC-004" not in rule_ids


# ---------------------------------------------------------------------------
# AC-2: SEC-017 -- yaml.load without SafeLoader
# ---------------------------------------------------------------------------


class TestYamlUnsafeLoader:
    """SEC-017: yaml.load() without SafeLoader."""

    def test_yaml_load_no_loader_detected(self):
        sym = _make_symbol(calls=["load"], imports=["yaml"])
        source = b"import yaml\ndef func():\n    yaml.load(data)\n"
        sources = {_source_key(): source}
        findings, total, _ = scan_symbols([sym], symbol_sources=sources)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-017" in rule_ids

    def test_yaml_load_full_loader_detected(self):
        sym = _make_symbol(calls=["load"], imports=["yaml"])
        source = b"import yaml\ndef func():\n    yaml.load(data, Loader=yaml.FullLoader)\n"
        sources = {_source_key(): source}
        findings, total, _ = scan_symbols([sym], symbol_sources=sources)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-017" in rule_ids

    def test_yaml_load_unsafe_loader_detected(self):
        sym = _make_symbol(calls=["load"], imports=["yaml"])
        source = b"import yaml\ndef func():\n    yaml.load(data, Loader=yaml.UnsafeLoader)\n"
        sources = {_source_key(): source}
        findings, total, _ = scan_symbols([sym], symbol_sources=sources)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-017" in rule_ids

    def test_yaml_load_safe_loader_not_detected(self):
        sym = _make_symbol(calls=["load"], imports=["yaml"])
        source = b"import yaml\ndef func():\n    yaml.load(data, Loader=yaml.SafeLoader)\n"
        sources = {_source_key(): source}
        findings, total, _ = scan_symbols([sym], symbol_sources=sources)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-017" not in rule_ids

    def test_yaml_load_csafe_loader_not_detected(self):
        sym = _make_symbol(calls=["load"], imports=["yaml"])
        source = b"import yaml\ndef func():\n    yaml.load(data, Loader=yaml.CSafeLoader)\n"
        sources = {_source_key(): source}
        findings, total, _ = scan_symbols([sym], symbol_sources=sources)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-017" not in rule_ids

    def test_yaml_safe_load_not_detected(self):
        sym = _make_symbol(calls=["safe_load"], imports=["yaml"])
        source = b"import yaml\ndef func():\n    yaml.safe_load(data)\n"
        sources = {_source_key(): source}
        findings, total, _ = scan_symbols([sym], symbol_sources=sources)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-017" not in rule_ids

    def test_yaml_load_suppresses_sec011(self):
        sym = _make_symbol(calls=["load"], imports=["yaml"])
        source = b"import yaml\ndef func():\n    yaml.load(data)\n"
        sources = {_source_key(): source}
        findings, total, _ = scan_symbols([sym], symbol_sources=sources)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-017" in rule_ids
        assert "SEC-011" not in rule_ids


# ---------------------------------------------------------------------------
# AC-3: SEC-018 -- bind to all interfaces (0.0.0.0)
# ---------------------------------------------------------------------------


class TestBindAllInterfaces:
    """SEC-018: binding to 0.0.0.0."""

    def test_bind_0000_tuple_detected(self):
        sym = _make_symbol(calls=["bind"], imports=["socket"])
        source = b'import socket\ndef func():\n    sock.bind(("0.0.0.0", 8080))\n'
        sources = {_source_key(): source}
        findings, total, _ = scan_symbols([sym], symbol_sources=sources)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-018" in rule_ids

    def test_bind_localhost_tuple_not_detected(self):
        sym = _make_symbol(calls=["bind"], imports=["socket"])
        source = b'import socket\ndef func():\n    sock.bind(("127.0.0.1", 8080))\n'
        sources = {_source_key(): source}
        findings, total, _ = scan_symbols([sym], symbol_sources=sources)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-018" not in rule_ids

    def test_run_host_0000_detected(self):
        sym = _make_symbol(calls=["run"], imports=["flask"])
        source = b'from flask import Flask\ndef func():\n    app.run(host="0.0.0.0")\n'
        sources = {_source_key(): source}
        findings, total, _ = scan_symbols([sym], symbol_sources=sources)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-018" in rule_ids

    def test_run_host_localhost_not_detected(self):
        sym = _make_symbol(calls=["run"], imports=["flask"])
        source = b'from flask import Flask\ndef func():\n    app.run(host="127.0.0.1")\n'
        sources = {_source_key(): source}
        findings, total, _ = scan_symbols([sym], symbol_sources=sources)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-018" not in rule_ids


# ---------------------------------------------------------------------------
# AC-4: SEC-019 -- debug=True
# ---------------------------------------------------------------------------


class TestDebugTrue:
    """SEC-019: debug mode enabled."""

    def test_debug_true_detected(self):
        sym = _make_symbol(calls=["run"], imports=["flask"])
        source = b"from flask import Flask\ndef func():\n    app.run(debug=True)\n"
        sources = {_source_key(): source}
        findings, total, _ = scan_symbols([sym], symbol_sources=sources)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-019" in rule_ids

    def test_debug_false_not_detected(self):
        sym = _make_symbol(calls=["run"], imports=["flask"])
        source = b"from flask import Flask\ndef func():\n    app.run(debug=False)\n"
        sources = {_source_key(): source}
        findings, total, _ = scan_symbols([sym], symbol_sources=sources)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-019" not in rule_ids


# ---------------------------------------------------------------------------
# AC-5: Graceful degradation when source is unavailable
# ---------------------------------------------------------------------------


class TestGracefulDegradation:
    """Arg-sensitive rules degrade gracefully without source."""

    def test_no_source_skips_arg_rules(self):
        sym = _make_symbol(calls=["run"], imports=["subprocess"])
        findings, total, _ = scan_symbols([sym], symbol_sources=None)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-016" not in rule_ids
        assert "SEC-004" in rule_ids

    def test_no_source_yaml_fallback(self):
        sym = _make_symbol(calls=["load"], imports=["yaml"])
        findings, total, _ = scan_symbols([sym], symbol_sources=None)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-017" not in rule_ids
        assert "SEC-011" in rule_ids

    def test_empty_source_dict_no_crash(self):
        sym = _make_symbol(calls=["run"], imports=["subprocess"])
        findings, total, _ = scan_symbols([sym], symbol_sources={})
        rule_ids = {f["rule_id"] for f in findings}
        # Arg rules skipped (no key match), fallback fires
        assert "SEC-016" not in rule_ids
        assert "SEC-004" in rule_ids

    def test_missing_key_skips_arg_rule(self):
        sym = _make_symbol(calls=["run"], imports=["subprocess"])
        # Key doesn't match: symbol is at test.py:1:func but source keyed to other.py:5:f
        sources = {"other.py:5:f": b"import subprocess\ndef f():\n    subprocess.run(cmd, shell=True)\n"}
        findings, total, _ = scan_symbols([sym], symbol_sources=sources)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-016" not in rule_ids
        assert "SEC-004" in rule_ids


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge cases for argument-sensitive rules."""

    def test_multiple_rules_in_one_symbol(self):
        sym = _make_symbol(calls=["run", "load"], imports=["subprocess", "yaml"])
        source = (
            b"import subprocess\nimport yaml\n"
            b"def func():\n"
            b"    subprocess.run(cmd, shell=True)\n"
            b"    yaml.load(data)\n"
        )
        sources = {_source_key(): source}
        findings, total, _ = scan_symbols([sym], symbol_sources=sources)
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-016" in rule_ids
        assert "SEC-017" in rule_ids

    def test_one_finding_per_rule_not_per_call(self):
        sym = _make_symbol(calls=["run", "call"], imports=["subprocess"])
        source = (
            b"import subprocess\n"
            b"def func():\n"
            b"    subprocess.run(cmd, shell=True)\n"
            b"    subprocess.call(cmd, shell=True)\n"
        )
        sources = {_source_key(): source}
        findings, total, _ = scan_symbols([sym], symbol_sources=sources)
        sec016_findings = [f for f in findings if f["rule_id"] == "SEC-016"]
        assert len(sec016_findings) == 1
