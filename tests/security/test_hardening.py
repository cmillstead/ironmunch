"""Comprehensive hardening tests for codesight-mcp parser."""

import json
from pathlib import Path

import pytest

from codesight_mcp.parser import parse_file, Symbol, make_symbol_id, compute_content_hash


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _fixture(language: str, filename: str) -> tuple[str, str]:
    """Return (content, filepath) for a fixture file."""
    path = FIXTURES / language / filename
    content = path.read_text(encoding="utf-8")
    return content, path.name


def _kinds(symbols: list[Symbol]) -> dict[str, list[Symbol]]:
    """Group symbols by kind for easier assertions."""
    result: dict[str, list[Symbol]] = {}
    for s in symbols:
        result.setdefault(s.kind, []).append(s)
    return result


def _names(symbols: list[Symbol]) -> set[str]:
    """Get set of symbol names."""
    return {s.name for s in symbols}


def _by_name(symbols: list[Symbol], name: str) -> Symbol:
    """Find a symbol by name (first match)."""
    for s in symbols:
        if s.name == name:
            return s
    raise AssertionError(f"No symbol named '{name}' found. Available: {_names(symbols)}")


# ===========================================================================
# 1. Per-Language Extraction
# ===========================================================================


class TestPerLanguageExtraction:
    """Verify symbol extraction for each supported language fixture."""

    # -- Python ----------------------------------------------------------

    def test_python_symbol_count(self):
        content, fname = _fixture("python", "sample.py")
        symbols = parse_file(content, fname, "python")
        # Expected: MAX_RETRIES (constant), UserService (class),
        # get_user (method), delete_user (method), authenticate (function)
        assert len(symbols) >= 5

    def test_python_class(self):
        content, fname = _fixture("python", "sample.py")
        symbols = parse_file(content, fname, "python")
        cls = _by_name(symbols, "UserService")
        assert cls.kind == "class"
        assert cls.language == "python"

    def test_python_methods(self):
        content, fname = _fixture("python", "sample.py")
        symbols = parse_file(content, fname, "python")
        grouped = _kinds(symbols)
        methods = grouped.get("method", [])
        method_names = {m.name for m in methods}
        assert "get_user" in method_names
        assert "delete_user" in method_names
        for m in methods:
            assert m.parent is not None, f"Method {m.name} should have a parent"

    def test_python_function(self):
        content, fname = _fixture("python", "sample.py")
        symbols = parse_file(content, fname, "python")
        func = _by_name(symbols, "authenticate")
        assert func.kind == "function"

    def test_python_constant(self):
        content, fname = _fixture("python", "sample.py")
        symbols = parse_file(content, fname, "python")
        const = _by_name(symbols, "MAX_RETRIES")
        assert const.kind == "constant"

    def test_python_qualified_names(self):
        content, fname = _fixture("python", "sample.py")
        symbols = parse_file(content, fname, "python")
        get_user = _by_name(symbols, "get_user")
        assert get_user.qualified_name == "UserService.get_user"
        delete_user = _by_name(symbols, "delete_user")
        assert delete_user.qualified_name == "UserService.delete_user"

    # -- JavaScript ------------------------------------------------------

    def test_javascript_class(self):
        content, fname = _fixture("javascript", "sample.js")
        symbols = parse_file(content, fname, "javascript")
        cls = _by_name(symbols, "UserService")
        assert cls.kind == "class"

    def test_javascript_function(self):
        content, fname = _fixture("javascript", "sample.js")
        symbols = parse_file(content, fname, "javascript")
        func = _by_name(symbols, "authenticate")
        assert func.kind == "function"

    def test_javascript_method(self):
        content, fname = _fixture("javascript", "sample.js")
        symbols = parse_file(content, fname, "javascript")
        grouped = _kinds(symbols)
        methods = grouped.get("method", [])
        method_names = {m.name for m in methods}
        assert "getUser" in method_names

    def test_javascript_qualified_names(self):
        content, fname = _fixture("javascript", "sample.js")
        symbols = parse_file(content, fname, "javascript")
        # method_definition nodes inside class get parent set
        get_user = _by_name(symbols, "getUser")
        assert "UserService" in get_user.qualified_name

    # -- TypeScript ------------------------------------------------------

    def test_typescript_class(self):
        content, fname = _fixture("typescript", "sample.ts")
        symbols = parse_file(content, fname, "typescript")
        cls = _by_name(symbols, "UserService")
        assert cls.kind == "class"

    def test_typescript_function(self):
        content, fname = _fixture("typescript", "sample.ts")
        symbols = parse_file(content, fname, "typescript")
        func = _by_name(symbols, "authenticate")
        assert func.kind == "function"

    def test_typescript_interface(self):
        content, fname = _fixture("typescript", "sample.ts")
        symbols = parse_file(content, fname, "typescript")
        iface = _by_name(symbols, "User")
        assert iface.kind == "type"

    def test_typescript_type_alias(self):
        content, fname = _fixture("typescript", "sample.ts")
        symbols = parse_file(content, fname, "typescript")
        alias = _by_name(symbols, "UserID")
        assert alias.kind == "type"

    def test_typescript_method(self):
        content, fname = _fixture("typescript", "sample.ts")
        symbols = parse_file(content, fname, "typescript")
        get_user = _by_name(symbols, "getUser")
        assert get_user.kind == "method"
        assert "UserService" in get_user.qualified_name

    # -- Go --------------------------------------------------------------

    def test_go_functions(self):
        content, fname = _fixture("go", "sample.go")
        symbols = parse_file(content, fname, "go")
        grouped = _kinds(symbols)
        func_names = {f.name for f in grouped.get("function", [])}
        assert "GetUser" in func_names
        assert "Authenticate" in func_names

    def test_go_type(self):
        content, fname = _fixture("go", "sample.go")
        symbols = parse_file(content, fname, "go")
        user = _by_name(symbols, "User")
        assert user.kind == "type"

    def test_go_function_kind(self):
        content, fname = _fixture("go", "sample.go")
        symbols = parse_file(content, fname, "go")
        get_user = _by_name(symbols, "GetUser")
        assert get_user.kind == "function"

    # -- Rust ------------------------------------------------------------

    def test_rust_struct(self):
        content, fname = _fixture("rust", "sample.rs")
        symbols = parse_file(content, fname, "rust")
        user = _by_name(symbols, "User")
        assert user.kind == "type"

    def test_rust_impl_block_not_extracted(self):
        """impl_item is in symbol_node_types but has no name_fields entry,
        so the extractor skips it (returns None from _extract_name).
        Functions inside impl are still extracted as top-level functions."""
        content, fname = _fixture("rust", "sample.rs")
        symbols = parse_file(content, fname, "rust")
        grouped = _kinds(symbols)
        # impl blocks are skipped because name extraction fails
        impl_syms = grouped.get("class", [])
        assert len(impl_syms) == 0

    def test_rust_fn_in_impl(self):
        """Without the impl parent being extracted, 'new' appears as a
        top-level function rather than a method."""
        content, fname = _fixture("rust", "sample.rs")
        symbols = parse_file(content, fname, "rust")
        new_sym = _by_name(symbols, "new")
        assert new_sym.kind == "function"
        assert new_sym.parent is None

    def test_rust_free_function(self):
        content, fname = _fixture("rust", "sample.rs")
        symbols = parse_file(content, fname, "rust")
        auth = _by_name(symbols, "authenticate")
        assert auth.kind == "function"

    # -- Java ------------------------------------------------------------

    def test_java_class(self):
        content, fname = _fixture("java", "Sample.java")
        symbols = parse_file(content, fname, "java")
        cls = _by_name(symbols, "Sample")
        assert cls.kind == "class"

    def test_java_methods(self):
        content, fname = _fixture("java", "Sample.java")
        symbols = parse_file(content, fname, "java")
        grouped = _kinds(symbols)
        methods = grouped.get("method", [])
        method_names = {m.name for m in methods}
        assert "getUser" in method_names
        assert "authenticate" in method_names

    def test_java_method_qualified_names(self):
        content, fname = _fixture("java", "Sample.java")
        symbols = parse_file(content, fname, "java")
        get_user = _by_name(symbols, "getUser")
        assert "Sample" in get_user.qualified_name


# ===========================================================================
# 2. Overload Disambiguation
# ===========================================================================


class TestOverloadDisambiguation:
    """Verify that duplicate symbol IDs get ~1, ~2 suffixes."""

    OVERLOADED_SRC = '''\
def process(x: int) -> int:
    return x

def process(x: str) -> str:
    return x.upper()
'''

    def test_duplicate_ids_get_ordinal_suffix(self):
        symbols = parse_file(self.OVERLOADED_SRC, "overloads.py", "python")
        process_syms = [s for s in symbols if s.name == "process"]
        assert len(process_syms) == 2

        ids = [s.id for s in process_syms]
        assert ids[0].endswith("~1"), f"Expected ~1 suffix, got {ids[0]}"
        assert ids[1].endswith("~2"), f"Expected ~2 suffix, got {ids[1]}"

    def test_non_duplicate_ids_unchanged(self):
        content, fname = _fixture("python", "sample.py")
        symbols = parse_file(content, fname, "python")
        for s in symbols:
            assert "~" not in s.id, f"Symbol {s.name} has unexpected ordinal: {s.id}"


# ===========================================================================
# 3. Content Hashing
# ===========================================================================


class TestContentHashing:
    """Verify content_hash is populated and consistent."""

    def test_all_symbols_have_content_hash(self):
        content, fname = _fixture("python", "sample.py")
        symbols = parse_file(content, fname, "python")
        for s in symbols:
            assert s.content_hash, f"Symbol {s.name} missing content_hash"
            assert len(s.content_hash) == 64, "SHA-256 hex should be 64 chars"

    def test_reparse_produces_same_hashes(self):
        content, fname = _fixture("python", "sample.py")
        symbols_a = parse_file(content, fname, "python")
        symbols_b = parse_file(content, fname, "python")

        hashes_a = {s.name: s.content_hash for s in symbols_a}
        hashes_b = {s.name: s.content_hash for s in symbols_b}
        assert hashes_a == hashes_b

    def test_compute_content_hash_directly(self):
        data = b"hello world"
        h = compute_content_hash(data)
        assert len(h) == 64
        # Same input -> same hash
        assert compute_content_hash(data) == h
        # Different input -> different hash
        assert compute_content_hash(b"different") != h


# ===========================================================================
# 4. Determinism
# ===========================================================================


class TestDeterminism:
    """Parse the same file twice and confirm identical output."""

    @pytest.mark.parametrize("language,filename", [
        ("python", "sample.py"),
        ("javascript", "sample.js"),
        ("typescript", "sample.ts"),
        ("go", "sample.go"),
        ("rust", "sample.rs"),
        ("java", "Sample.java"),
    ])
    def test_deterministic_ids_and_hashes(self, language, filename):
        content, fname = _fixture(language, filename)
        run1 = parse_file(content, fname, language)
        run2 = parse_file(content, fname, language)

        assert len(run1) == len(run2), f"Symbol count mismatch for {language}"

        for s1, s2 in zip(run1, run2):
            assert s1.id == s2.id, f"ID mismatch: {s1.id} vs {s2.id}"
            assert s1.content_hash == s2.content_hash, (
                f"Hash mismatch for {s1.name}: {s1.content_hash} vs {s2.content_hash}"
            )
            assert s1.kind == s2.kind
            assert s1.qualified_name == s2.qualified_name
