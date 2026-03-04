"""Tests for the parser module (Phase 1)."""

import pytest
from ironmunch.parser import parse_file, Symbol
from ironmunch.parser.extractor import _get_parser


PYTHON_SOURCE = '''
class MyClass:
    """A sample class."""
    def method(self, x: int) -> str:
        """Do something."""
        return str(x)

def standalone(a, b):
    """Standalone function."""
    return a + b

MAX_SIZE = 100
'''


def test_parse_python():
    """Test Python parsing extracts expected symbols."""
    symbols = parse_file(PYTHON_SOURCE, "test.py", "python")

    # Should have class, method, function, constant
    assert len(symbols) >= 3

    # Check class
    class_syms = [s for s in symbols if s.kind == "class"]
    assert len(class_syms) == 1
    assert class_syms[0].name == "MyClass"
    assert "A sample class" in class_syms[0].docstring

    # Check method
    method_syms = [s for s in symbols if s.kind == "method"]
    assert len(method_syms) == 1
    assert method_syms[0].name == "method"
    assert method_syms[0].parent is not None

    # Check standalone function
    func_syms = [s for s in symbols if s.kind == "function" and s.name == "standalone"]
    assert len(func_syms) == 1
    assert "Standalone function" in func_syms[0].docstring

    # Check constant
    const_syms = [s for s in symbols if s.kind == "constant"]
    assert len(const_syms) == 1
    assert const_syms[0].name == "MAX_SIZE"


def test_symbol_id_format():
    """Test symbol ID generation."""
    from ironmunch.parser import make_symbol_id

    assert make_symbol_id("src/main.py", "MyClass.method", "method") == "src/main.py::MyClass.method#method"
    assert make_symbol_id("test.py", "standalone", "function") == "test.py::standalone#function"
    # Without kind falls back to no suffix
    assert make_symbol_id("test.py", "foo") == "test.py::foo"


def test_unknown_language_returns_empty():
    """Test that unknown languages return empty list."""
    result = parse_file("some code", "test.unknown", "unknown")
    assert result == []


def test_symbol_byte_offsets():
    """Test that byte offsets are correct."""
    symbols = parse_file(PYTHON_SOURCE, "test.py", "python")

    for sym in symbols:
        # Byte offset should be non-negative
        assert sym.byte_offset >= 0
        assert sym.byte_length > 0

        # Line numbers should be positive
        assert sym.line > 0
        assert sym.end_line >= sym.line


class TestGetParserAllowlist:
    """SEC-LOW-5: _get_parser must reject unsupported languages."""

    def test_unsupported_language_raises(self):
        with pytest.raises(ValueError, match="Unsupported language"):
            _get_parser("malicious")

    def test_supported_language_works(self):
        parser = _get_parser("python")
        assert parser is not None


class TestConstantSignatureSanitization:
    """SEC-HIGH-2: Constant signatures must not leak secrets to external APIs."""

    def test_database_url_password_redacted(self):
        """Connection string password must not appear in constant signature."""
        source = 'DATABASE_URL = "postgres://admin:secretpass@localhost/db"\n'
        symbols = parse_file(source, "config.py", "python")
        const_syms = [s for s in symbols if s.kind == "constant"]
        assert len(const_syms) == 1, "Expected one constant symbol"
        assert "secretpass" not in const_syms[0].signature, (
            f"Secret leaked in signature: {const_syms[0].signature!r}"
        )

    def test_api_key_redacted_in_signature(self):
        """API key value matching sk-* pattern must be redacted to <REDACTED>."""
        source = 'API_KEY = "sk-abc123xyz456789012345"\n'
        symbols = parse_file(source, "config.py", "python")
        const_syms = [s for s in symbols if s.kind == "constant"]
        assert len(const_syms) == 1, "Expected one constant symbol"
        assert "<REDACTED>" in const_syms[0].signature, (
            f"Expected <REDACTED> in signature: {const_syms[0].signature!r}"
        )
