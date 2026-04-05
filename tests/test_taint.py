"""Tests for trace_taint tool and taint path analysis.

Tier 1: Unit tests for source/sink detection and defaults.
Tier 2: End-to-end integration tests with real parsed code and CodeGraph.
"""

import shutil


from codesight_mcp.tools.trace_taint import _DEFAULT_SOURCE_CALLS, _trace_taint_from_symbols
from codesight_mcp.security_rules import scan_symbols


# ===========================================================================
# Tier 1: Unit tests
# ===========================================================================


class TestSourceCallsDefined:
    """_DEFAULT_SOURCE_CALLS contains expected source API names."""

    def test_contains_input(self):
        assert "input" in _DEFAULT_SOURCE_CALLS

    def test_contains_read(self):
        assert "read" in _DEFAULT_SOURCE_CALLS

    def test_contains_recv(self):
        assert "recv" in _DEFAULT_SOURCE_CALLS

    def test_contains_readline(self):
        assert "readline" in _DEFAULT_SOURCE_CALLS

    def test_contains_getenv(self):
        assert "getenv" in _DEFAULT_SOURCE_CALLS

    def test_is_frozenset(self):
        assert isinstance(_DEFAULT_SOURCE_CALLS, frozenset)


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


class TestSinkDetection:
    """scan_symbols finds dangerous patterns that act as taint sinks."""

    def test_eval_detected_as_sink(self):
        symbols = [_make_symbol(calls=["eval"])]
        findings, total, _ = scan_symbols(symbols, min_severity="high")
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-001" in rule_ids

    def test_os_system_detected_as_sink(self):
        symbols = [_make_symbol(calls=["system"], imports=["os"])]
        findings, total, _ = scan_symbols(symbols, min_severity="high")
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-003" in rule_ids

    def test_exec_detected_as_sink(self):
        symbols = [_make_symbol(calls=["exec"])]
        findings, total, _ = scan_symbols(symbols, min_severity="high")
        rule_ids = {f["rule_id"] for f in findings}
        assert "SEC-002" in rule_ids


# ===========================================================================
# Tier 2: End-to-end with real parsed code
# ===========================================================================


# Test code snippets contain dangerous API references (os.system, eval, exec)
# intentionally — they are the taint sinks being tested.

_CODE_SOURCE_TO_SINK = '''\
import os

def get_input():
    data = input("enter: ")
    return process(data)

def process(data):
    return execute(data)

def execute(cmd):
    os.system(cmd)
'''

_CODE_SINK_ONLY = '''\
import os
def safe():
    os.system('ls')
'''

_CODE_SOURCE_ONLY = '''\
def get_data():
    return input("x")

def process(data):
    return len(data)
'''

_CODE_CUSTOM_SOURCE = '''\
def my_input():
    return my_custom_read()

def process(x):
    return x
'''


class TestTraceTaintE2EWithPath:
    """Index real Python with connected source->sink chain, verify path found."""

    def test_trace_taint_e2e_with_path(self):
        from codesight_mcp.parser.extractor import parse_file
        from codesight_mcp.parser.graph import CodeGraph
        from dataclasses import asdict

        symbols = parse_file(_CODE_SOURCE_TO_SINK, "app.py", "python")
        sym_dicts = [asdict(s) for s in symbols]

        # Verify source has forward edges
        src = [s for s in sym_dicts if s["name"] == "get_input"][0]
        assert "input" in src.get("calls", []), f"Expected input in calls: {src['calls']}"
        assert "process" in src.get("calls", []), f"Expected process in calls: {src['calls']}"

        graph = CodeGraph.build(sym_dicts)
        result = _trace_taint_from_symbols(sym_dicts, graph)

        assert result["summary"]["sources_found"] >= 1, f"No sources: {result['summary']}"
        assert result["summary"]["sinks_found"] >= 1, f"No sinks: {result['summary']}"
        # Path should exist: get_input -> process -> execute
        assert result["summary"]["paths_found"] >= 1, f"No paths found: {result}"
        # Verify path structure
        if result["taint_paths"]:
            path = result["taint_paths"][0]
            assert "source" in path
            assert "sink" in path
            assert "path" in path
            assert len(path["path"]) >= 2  # at least source and sink


class TestTraceNoSources:
    """Code with no input functions -> 0 sources, 0 paths."""

    def test_trace_no_sources(self):
        from codesight_mcp.parser.extractor import parse_file
        from codesight_mcp.parser.graph import CodeGraph
        from dataclasses import asdict

        symbols = parse_file(_CODE_SINK_ONLY, "safe.py", "python")
        sym_dicts = [asdict(s) for s in symbols]
        graph = CodeGraph.build(sym_dicts)
        result = _trace_taint_from_symbols(sym_dicts, graph)
        assert result["summary"]["sources_found"] == 0
        assert result["summary"]["paths_found"] == 0


class TestTraceNoSinks:
    """Code with input but no dangerous APIs -> 0 sinks, 0 paths."""

    def test_trace_no_sinks(self):
        from codesight_mcp.parser.extractor import parse_file
        from codesight_mcp.parser.graph import CodeGraph
        from dataclasses import asdict

        symbols = parse_file(_CODE_SOURCE_ONLY, "clean.py", "python")
        sym_dicts = [asdict(s) for s in symbols]
        graph = CodeGraph.build(sym_dicts)
        result = _trace_taint_from_symbols(sym_dicts, graph)
        assert result["summary"]["sinks_found"] == 0
        assert result["summary"]["paths_found"] == 0


class TestCustomSourceCalls:
    """Custom source_calls parameter overrides defaults."""

    def test_custom_source_calls(self):
        from codesight_mcp.parser.extractor import parse_file
        from codesight_mcp.parser.graph import CodeGraph
        from dataclasses import asdict

        symbols = parse_file(_CODE_CUSTOM_SOURCE, "custom.py", "python")
        sym_dicts = [asdict(s) for s in symbols]
        graph = CodeGraph.build(sym_dicts)
        result = _trace_taint_from_symbols(
            sym_dicts, graph, source_calls=frozenset({"my_custom_read"}),
        )
        assert result["summary"]["sources_found"] >= 1


# ===========================================================================
# Registry test
# ===========================================================================


class TestToolRegistered:
    """trace_taint tool is registered with correct flags."""

    def test_tool_registered(self):
        import codesight_mcp.tools.trace_taint  # noqa: F401 -- trigger registration
        from codesight_mcp.tools.registry import get_all_specs

        specs = get_all_specs()
        assert "trace_taint" in specs, "trace_taint not in registry"
        spec = specs["trace_taint"]
        assert spec.untrusted is True
        assert spec.annotations is not None
        assert spec.annotations.readOnlyHint is True


# ===========================================================================
# Semgrep availability test
# ===========================================================================


class TestSemgrepAvailableField:
    """shutil.which('semgrep') result is consistent with runtime."""

    def test_semgrep_available_field(self):
        result = shutil.which("semgrep")
        # Just verify the call works and returns str or None
        assert result is None or isinstance(result, str)
