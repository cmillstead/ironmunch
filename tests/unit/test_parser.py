"""Tests for the parser module (Phase 1)."""

import pytest
from codesight_mcp.parser import parse_file, Symbol
from codesight_mcp.parser.extractor import _get_parser


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
    from codesight_mcp.parser import make_symbol_id

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


class TestSymbolIdNoCollision:
    """Task 25: make_symbol_id must not produce collisions."""

    def test_symbol_id_no_collision(self):
        """Files like 'foo::bar.py' and 'foo__bar.py' must produce different IDs."""
        from codesight_mcp.parser import make_symbol_id

        id1 = make_symbol_id("foo::bar.py", "func", "function")
        id2 = make_symbol_id("foo__bar.py", "func", "function")
        assert id1 != id2, f"Collision: {id1!r} == {id2!r}"

    def test_symbol_id_hash_no_collision(self):
        """Qualified names with '#' must not collide with those using '_'."""
        from codesight_mcp.parser import make_symbol_id

        id1 = make_symbol_id("a.py", "Foo#bar", "method")
        id2 = make_symbol_id("a.py", "Foo_bar", "method")
        assert id1 != id2, f"Collision: {id1!r} == {id2!r}"


class TestCollectCallsDepthLimit:
    """Task 23: _collect_calls must respect depth limit."""

    def test_collect_calls_depth_limit(self):
        """_extract_calls should not crash on deeply nested function bodies."""
        # Build a Python source with deeply nested if blocks (300 levels)
        lines = ["def outer():"]
        for i in range(300):
            indent = "    " * (i + 1)
            lines.append(f"{indent}if True:")
        # Place a function call at the deepest level
        deepest_indent = "    " * 301
        lines.append(f"{deepest_indent}deep_call()")
        source = "\n".join(lines) + "\n"

        symbols = parse_file(source, "deep.py", "python")
        # Should parse without crashing (RecursionError)
        assert len(symbols) >= 1
        func_syms = [s for s in symbols if s.kind == "function"]
        assert len(func_syms) == 1
        # The deeply nested call may or may not be found due to depth limit,
        # but the key thing is no crash
        assert func_syms[0].name == "outer"


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


class TestFunctionSignatureSanitization:
    """SEC-HIGH-1: Function/method/class signatures must not leak secrets at parse time."""

    def test_bearer_token_in_default_arg_redacted(self):
        """Bearer token in default parameter value must be redacted in signature."""
        # Use concatenation to avoid GitHub push protection matching literal token
        token = "Bearer " + "abc123defghijklmnopqrs"
        source = f'def connect(host, pw="{token}"): pass\n'
        symbols = parse_file(source, "net.py", "python")
        func_syms = [s for s in symbols if s.kind == "function"]
        assert len(func_syms) == 1, "Expected one function symbol"
        assert "abc123defghijklmnopqrs" not in func_syms[0].signature, (
            f"Secret leaked in signature: {func_syms[0].signature!r}"
        )
        assert "<REDACTED>" in func_syms[0].signature, (
            f"Expected <REDACTED> in signature: {func_syms[0].signature!r}"
        )

    def test_sk_live_api_key_in_default_arg_redacted(self):
        """sk-live_ API key in default parameter value must be redacted in signature."""
        # Use concatenation to avoid GitHub push protection matching literal token
        api_key = "sk-live_" + "abcdef12345678901234567890"
        source = f'def build(api_key="{api_key}"): pass\n'
        symbols = parse_file(source, "builder.py", "python")
        func_syms = [s for s in symbols if s.kind == "function"]
        assert len(func_syms) == 1, "Expected one function symbol"
        assert "abcdef12345678901234567890" not in func_syms[0].signature, (
            f"Secret leaked in signature: {func_syms[0].signature!r}"
        )
        assert "<REDACTED>" in func_syms[0].signature, (
            f"Expected <REDACTED> in signature: {func_syms[0].signature!r}"
        )

    def test_normal_function_signature_unchanged(self):
        """Normal function signature without secrets must be returned unchanged."""
        source = "def add(a: int, b: int = 0) -> int: pass\n"
        symbols = parse_file(source, "math.py", "python")
        func_syms = [s for s in symbols if s.kind == "function"]
        assert len(func_syms) == 1, "Expected one function symbol"
        assert "add" in func_syms[0].signature
        assert "a: int" in func_syms[0].signature
        assert "b: int = 0" in func_syms[0].signature
        assert "<REDACTED>" not in func_syms[0].signature


class TestDecoratorSanitization:
    """SEC-MED-1: Decorator values must not leak secrets at parse time."""

    def test_decorator_with_token_redacted(self):
        """Token value in decorator argument must be redacted."""
        # Use concatenation to avoid GitHub push protection matching literal token
        token = "ghp_" + "A" * 36
        source = (
            f'@requires_auth(token="{token}")\n'
            "def protected(): pass\n"
        )
        symbols = parse_file(source, "api.py", "python")
        func_syms = [s for s in symbols if s.kind == "function"]
        assert len(func_syms) == 1, "Expected one function symbol"
        assert len(func_syms[0].decorators) == 1, "Expected one decorator"
        assert "A" * 36 not in func_syms[0].decorators[0], (
            f"Secret leaked in decorator: {func_syms[0].decorators[0]!r}"
        )
        assert "<REDACTED>" in func_syms[0].decorators[0], (
            f"Expected <REDACTED> in decorator: {func_syms[0].decorators[0]!r}"
        )


class TestDocstringSanitization:
    """SEC-HIGH-1: Docstring content must not leak secrets at parse time."""

    def test_password_in_docstring_redacted(self):
        """Password literal in docstring must be redacted to <REDACTED>."""
        # Use concatenation to avoid GitHub push protection matching literal token
        secret = "s3cr3t" + "123"
        source = (
            "def foo():\n"
            f'    """password=\'{secret}\' used here."""\n'
            "    pass\n"
        )
        symbols = parse_file(source, "db.py", "python")
        func_syms = [s for s in symbols if s.kind == "function"]
        assert len(func_syms) == 1, "Expected one function symbol"
        assert secret not in (func_syms[0].docstring or ""), (
            f"Secret leaked in docstring: {func_syms[0].docstring!r}"
        )
        assert "<REDACTED>" in (func_syms[0].docstring or ""), (
            f"Expected <REDACTED> in docstring: {func_syms[0].docstring!r}"
        )

    def test_db_url_in_docstring_redacted(self):
        """Database URL with credentials in docstring must be redacted."""
        source = (
            "def connect():\n"
            '    """Use postgres://admin:Hunter2@prod.db.internal/mydb."""\n'
            "    pass\n"
        )
        symbols = parse_file(source, "db.py", "python")
        func_syms = [s for s in symbols if s.kind == "function"]
        assert len(func_syms) == 1, "Expected one function symbol"
        assert "Hunter2" not in (func_syms[0].docstring or ""), (
            f"Secret leaked in docstring: {func_syms[0].docstring!r}"
        )
        assert "<REDACTED>" in (func_syms[0].docstring or ""), (
            f"Expected <REDACTED> in docstring: {func_syms[0].docstring!r}"
        )

    def test_normal_docstring_unchanged(self):
        """Normal docstring without secrets must be returned unchanged."""
        source = (
            "def add(a, b):\n"
            '    """Add two numbers and return the result."""\n'
            "    return a + b\n"
        )
        symbols = parse_file(source, "math.py", "python")
        func_syms = [s for s in symbols if s.kind == "function"]
        assert len(func_syms) == 1, "Expected one function symbol"
        assert "Add two numbers" in (func_syms[0].docstring or ""), (
            f"Normal docstring was altered: {func_syms[0].docstring!r}"
        )
        assert "<REDACTED>" not in (func_syms[0].docstring or "")


class TestGetSymbolSourceRedaction:
    """SEC-MED-3: Function body returned by get_symbol must have inline secrets redacted."""

    def test_function_body_secret_redacted_in_get_symbol(self, tmp_path):
        """A function body containing a Bearer token must be redacted in get_symbol output."""
        import json
        from pathlib import Path
        from codesight_mcp.storage.index_store import IndexStore
        from codesight_mcp.tools.get_symbol import get_symbol

        owner, name, sym_id = "test", "repo", "connect_abc"
        # Function body: header with a literal secret token
        body = "def connect():\n    return {\"Authorization\": \"Bearer " + "sk_live_" + "x" * 24 + "\"}\n"

        with (tmp_path / "main.py").open("w") as fh:
            fh.write(body)

        store = IndexStore(tmp_path)
        content_dir = store._content_dir(owner, name)
        content_dir.mkdir(parents=True, exist_ok=True)

        import hashlib, os
        dest = content_dir / "main.py"
        dest.write_bytes(body.encode())
        os.chmod(str(dest), 0o600)

        index_data = {
            "repo": name, "owner": owner, "name": name,
            "indexed_at": "2026-01-01T00:00:00",
            "index_version": 2, "file_hashes": {}, "git_head": "",
            "source_files": ["main.py"], "languages": {"python": 1},
            "symbols": [{
                "id": sym_id, "file": "main.py",
                "name": "connect", "qualified_name": "connect",
                "kind": "function", "language": "python",
                "signature": "def connect():",
                "docstring": "", "summary": "", "decorators": [],
                "keywords": [], "parent": None,
                "line": 1, "end_line": 2,
                "byte_offset": 0,
                "byte_length": len(body.encode()),
                "content_hash": hashlib.sha256(body.encode()).hexdigest(),
            }],
        }
        idx_path = Path(tmp_path) / f"{owner}__{name}.json"
        idx_path.write_text(json.dumps(index_data))

        result = get_symbol(repo=f"{owner}/{name}", symbol_id=sym_id, storage_path=str(tmp_path))

        assert "source" in result, "Expected 'source' field in get_symbol result"
        source_val = result["source"]
        secret = "sk_live_" + "x" * 24
        assert secret not in source_val, (
            "Literal secret token must be redacted in get_symbol source output: " + repr(source_val[:100])
        )
        assert "<REDACTED>" in source_val, (
            "Expected <REDACTED> in source output: " + repr(source_val[:100])
        )

    def test_normal_function_body_unchanged(self, tmp_path):
        """A function body without secrets must be returned unchanged."""
        import json
        from pathlib import Path
        from codesight_mcp.storage.index_store import IndexStore
        from codesight_mcp.tools.get_symbol import get_symbol

        owner, name, sym_id = "test", "repo2", "add_abc"
        body = "def add(a, b):\n    return a + b\n"

        store = IndexStore(tmp_path)
        content_dir = store._content_dir(owner, name)
        content_dir.mkdir(parents=True, exist_ok=True)

        import hashlib, os
        dest = content_dir / "math.py"
        dest.write_bytes(body.encode())
        os.chmod(str(dest), 0o600)

        index_data = {
            "repo": name, "owner": owner, "name": name,
            "indexed_at": "2026-01-01T00:00:00",
            "index_version": 2, "file_hashes": {}, "git_head": "",
            "source_files": ["math.py"], "languages": {"python": 1},
            "symbols": [{
                "id": sym_id, "file": "math.py",
                "name": "add", "qualified_name": "add",
                "kind": "function", "language": "python",
                "signature": "def add(a, b):",
                "docstring": "", "summary": "", "decorators": [],
                "keywords": [], "parent": None,
                "line": 1, "end_line": 2,
                "byte_offset": 0,
                "byte_length": len(body.encode()),
                "content_hash": hashlib.sha256(body.encode()).hexdigest(),
            }],
        }
        idx_path = Path(tmp_path) / f"{owner}__{name}.json"
        idx_path.write_text(json.dumps(index_data))

        result = get_symbol(repo=f"{owner}/{name}", symbol_id=sym_id, storage_path=str(tmp_path))

        assert "source" in result
        assert "return a + b" in result["source"]
        assert "<REDACTED>" not in result["source"]
