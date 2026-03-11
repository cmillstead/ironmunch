"""Tests for get_dead_code tool (Task 18)."""

import hashlib

import pytest

from codesight_mcp.tools.get_dead_code import (
    get_dead_code,
    _is_test_file,
    _is_entry_point,
)
from codesight_mcp.storage import IndexStore
from codesight_mcp.parser import Symbol


def _make_src_hash(src: str) -> str:
    return hashlib.sha256(src.encode("utf-8")).hexdigest()


def _make_indexed_repo(tmp_path, extra_symbols=None):
    """Create an index with symbols for dead code testing.

    Layout:
        app.py:
            def main():       -- calls helper
            def helper():     -- called by main
            def unused():     -- no callers (dead code)
            class MyClass:    -- no callers
                def __init__: -- entry point (dunder)
        test_app.py:
            def test_main():  -- test function
    """
    app_src = "def main():\n    helper()\n"
    helper_src = "def helper():\n    pass\n"
    unused_src = "def unused():\n    pass\n"
    class_src = "class MyClass:\n    def __init__(self):\n        pass\n"
    test_src = "def test_main():\n    main()\n"

    full_app = app_src + helper_src + unused_src + class_src
    full_test = test_src

    symbols = [
        Symbol(
            id="app.py::main#function",
            file="app.py",
            name="main",
            qualified_name="main",
            kind="function",
            language="python",
            signature="def main():",
            line=1, end_line=2,
            byte_offset=0, byte_length=len(app_src),
            content_hash=_make_src_hash(app_src),
            calls=["helper"],
        ),
        Symbol(
            id="app.py::helper#function",
            file="app.py",
            name="helper",
            qualified_name="helper",
            kind="function",
            language="python",
            signature="def helper():",
            line=3, end_line=4,
            byte_offset=len(app_src), byte_length=len(helper_src),
            content_hash=_make_src_hash(helper_src),
        ),
        Symbol(
            id="app.py::unused#function",
            file="app.py",
            name="unused",
            qualified_name="unused",
            kind="function",
            language="python",
            signature="def unused():",
            line=5, end_line=6,
            byte_offset=len(app_src) + len(helper_src),
            byte_length=len(unused_src),
            content_hash=_make_src_hash(unused_src),
        ),
        Symbol(
            id="app.py::MyClass#class",
            file="app.py",
            name="MyClass",
            qualified_name="MyClass",
            kind="class",
            language="python",
            signature="class MyClass:",
            line=7, end_line=9,
            byte_offset=len(app_src) + len(helper_src) + len(unused_src),
            byte_length=len(class_src),
            content_hash=_make_src_hash(class_src),
        ),
        Symbol(
            id="app.py::MyClass.__init__#method",
            file="app.py",
            name="__init__",
            qualified_name="MyClass.__init__",
            kind="method",
            language="python",
            signature="def __init__(self):",
            parent="app.py::MyClass#class",
            line=8, end_line=9,
            byte_offset=len(app_src) + len(helper_src) + len(unused_src) + len("class MyClass:\n"),
            byte_length=len("    def __init__(self):\n        pass\n"),
            content_hash=_make_src_hash("    def __init__(self):\n        pass\n"),
        ),
        Symbol(
            id="test_app.py::test_main#function",
            file="test_app.py",
            name="test_main",
            qualified_name="test_main",
            kind="function",
            language="python",
            signature="def test_main():",
            line=1, end_line=2,
            byte_offset=0, byte_length=len(test_src),
            content_hash=_make_src_hash(test_src),
            calls=["main"],
        ),
    ]

    if extra_symbols:
        symbols.extend(extra_symbols)

    store = IndexStore(base_path=str(tmp_path))
    content_dir = tmp_path / "local__testapp"
    content_dir.mkdir(parents=True, exist_ok=True)
    (content_dir / "app.py").write_text(full_app)
    (content_dir / "test_app.py").write_text(full_test)

    store.save_index(
        owner="local",
        name="testapp",
        source_files=["app.py", "test_app.py"],
        symbols=symbols,
        raw_files={"app.py": full_app, "test_app.py": full_test},
        languages={"python": 2},
    )
    return store, symbols


# ---------------------------------------------------------------------------
# _is_test_file helper
# ---------------------------------------------------------------------------


class TestIsTestFile:
    """Tests for _is_test_file helper."""

    def test_python_test_file(self):
        assert _is_test_file("test_app.py") is True
        assert _is_test_file("tests/test_foo.py") is True

    def test_python_test_suffix(self):
        assert _is_test_file("app_test.py") is True

    def test_js_test_file(self):
        assert _is_test_file("app.test.js") is True
        assert _is_test_file("src/__tests__/app.js") is True

    def test_ts_test_file(self):
        assert _is_test_file("app.test.ts") is True
        assert _is_test_file("app.test.tsx") is True

    def test_go_test_file(self):
        assert _is_test_file("app_test.go") is True

    def test_ruby_spec_file(self):
        assert _is_test_file("app_spec.rb") is True

    def test_java_test_file(self):
        assert _is_test_file("AppTest.java") is True

    def test_test_directory(self):
        assert _is_test_file("test/app.py") is True
        assert _is_test_file("tests/app.py") is True

    def test_non_test_file(self):
        assert _is_test_file("app.py") is False
        assert _is_test_file("src/main.py") is False
        assert _is_test_file("lib/utils.js") is False

    def test_non_test_file_with_test_substring_in_path(self):
        """Paths containing 'test' as a substring in dir names should not be flagged."""
        # "/test/" substring used to match these false positives
        assert _is_test_file("src/attestation/handler.py") is False
        assert _is_test_file("src/contest/models.py") is False
        assert _is_test_file("lib/latest/utils.py") is False
        assert _is_test_file("pkg/detest/runner.py") is False


# ---------------------------------------------------------------------------
# _is_entry_point helper
# ---------------------------------------------------------------------------


class TestIsEntryPoint:
    """Tests for _is_entry_point helper."""

    def test_main_is_entry_point(self):
        assert _is_entry_point({"name": "main"}) is True

    def test_init_is_entry_point(self):
        assert _is_entry_point({"name": "__init__"}) is True

    def test_dunder_methods_are_entry_points(self):
        for name in ("__str__", "__repr__", "__eq__", "__hash__", "__len__"):
            assert _is_entry_point({"name": name}) is True

    def test_test_functions_are_entry_points(self):
        assert _is_entry_point({"name": "test_foo"}) is True
        assert _is_entry_point({"name": "TestFoo"}) is True

    def test_decorated_entry_points(self):
        assert _is_entry_point({
            "name": "index",
            "decorators": ["@app.route('/')"],
        }) is True

    def test_regular_function_not_entry_point(self):
        assert _is_entry_point({"name": "helper"}) is False
        assert _is_entry_point({"name": "calculate_total"}) is False


# ---------------------------------------------------------------------------
# get_dead_code
# ---------------------------------------------------------------------------


class TestGetDeadCodeHappyPath:
    """Happy-path tests for get_dead_code."""

    def test_finds_unused_symbol(self, tmp_path):
        """Should detect the 'unused' function as dead code."""
        _make_indexed_repo(tmp_path)
        result = get_dead_code(
            repo="local/testapp",
            storage_path=str(tmp_path),
        )

        assert "error" not in result
        dead_names = [s["name"] for s in result["symbols"]]
        # 'unused' has no callers and is not an entry point
        assert any("unused" in n for n in dead_names)

    def test_does_not_flag_called_symbols(self, tmp_path):
        """Symbols with callers should not appear as dead code."""
        _make_indexed_repo(tmp_path)
        result = get_dead_code(
            repo="local/testapp",
            storage_path=str(tmp_path),
        )

        dead_ids = {s["id"] for s in result["symbols"]}
        # helper is called by main
        assert not any("helper" in sid for sid in dead_ids)

    def test_does_not_flag_entry_points(self, tmp_path):
        """Entry points like main and __init__ should not appear."""
        _make_indexed_repo(tmp_path)
        result = get_dead_code(
            repo="local/testapp",
            storage_path=str(tmp_path),
        )

        dead_names = [s["name"] for s in result["symbols"]]
        assert "main" not in dead_names
        assert "__init__" not in dead_names

    def test_excludes_test_files_by_default(self, tmp_path):
        """Symbols in test files should be excluded by default."""
        _make_indexed_repo(tmp_path)
        result = get_dead_code(
            repo="local/testapp",
            storage_path=str(tmp_path),
        )

        dead_files = {s["file"] for s in result["symbols"]}
        assert not any("test_" in f for f in dead_files)

    def test_includes_test_files_when_requested(self, tmp_path):
        """include_tests=True should include test file symbols."""
        _make_indexed_repo(tmp_path)
        result = get_dead_code(
            repo="local/testapp",
            include_tests=True,
            storage_path=str(tmp_path),
        )

        # test_main is a test function (entry point), so it's still filtered.
        # But the flag should at least not filter by file path.
        assert "error" not in result

    def test_returns_meta_envelope(self, tmp_path):
        """Result should include _meta with timing."""
        _make_indexed_repo(tmp_path)
        result = get_dead_code(
            repo="local/testapp",
            storage_path=str(tmp_path),
        )

        assert "_meta" in result
        assert "timing_ms" in result["_meta"]
        assert "dead_count" in result
        assert result["dead_count"] == len(result["symbols"])


class TestGetDeadCodeLanguageFilter:
    """Tests for language filter."""

    def test_filter_by_language(self, tmp_path):
        """Should only return symbols matching the language filter."""
        js_src = "function jsUnused() {}\n"
        extra = [
            Symbol(
                id="utils.js::jsUnused#function",
                file="utils.js",
                name="jsUnused",
                qualified_name="jsUnused",
                kind="function",
                language="javascript",
                signature="function jsUnused()",
                line=1, end_line=1,
                byte_offset=0, byte_length=len(js_src),
                content_hash=_make_src_hash(js_src),
            ),
        ]
        _make_indexed_repo(tmp_path, extra_symbols=extra)

        result = get_dead_code(
            repo="local/testapp",
            language="javascript",
            storage_path=str(tmp_path),
        )

        assert "error" not in result
        # Only JS symbols should appear
        for sym in result["symbols"]:
            assert sym["language"] == "javascript"

    def test_filter_excludes_other_languages(self, tmp_path):
        """Python filter should not return JavaScript symbols."""
        js_src = "function jsUnused() {}\n"
        extra = [
            Symbol(
                id="utils.js::jsUnused#function",
                file="utils.js",
                name="jsUnused",
                qualified_name="jsUnused",
                kind="function",
                language="javascript",
                signature="function jsUnused()",
                line=1, end_line=1,
                byte_offset=0, byte_length=len(js_src),
                content_hash=_make_src_hash(js_src),
            ),
        ]
        _make_indexed_repo(tmp_path, extra_symbols=extra)

        result = get_dead_code(
            repo="local/testapp",
            language="python",
            storage_path=str(tmp_path),
        )

        for sym in result["symbols"]:
            assert sym["language"] == "python"


class TestGetDeadCodeErrors:
    """Error-handling tests for get_dead_code."""

    def test_missing_repo_returns_error(self, tmp_path):
        """An unknown repo should return an error dict."""
        result = get_dead_code(
            repo="nobody/norepo",
            storage_path=str(tmp_path),
        )

        assert "error" in result


class TestGetDeadCodeEdgeCases:
    """Edge-case tests."""

    def test_empty_repo(self, tmp_path):
        """A repo with no symbols should return empty list."""
        store = IndexStore(base_path=str(tmp_path))
        content_dir = tmp_path / "local__emptyrepo"
        content_dir.mkdir(parents=True, exist_ok=True)
        store.save_index(
            owner="local",
            name="emptyrepo",
            source_files=[],
            symbols=[],
            raw_files={},
            languages={},
        )

        result = get_dead_code(
            repo="local/emptyrepo",
            storage_path=str(tmp_path),
        )

        assert "error" not in result
        assert result["dead_count"] == 0
        assert result["symbols"] == []

    def test_class_without_callers_is_flagged(self, tmp_path):
        """A class with no callers (not an entry point) should be flagged."""
        _make_indexed_repo(tmp_path)
        result = get_dead_code(
            repo="local/testapp",
            storage_path=str(tmp_path),
        )

        dead_names = [s["name"] for s in result["symbols"]]
        # MyClass has no callers and is not in _ENTRY_POINT_NAMES
        assert any("MyClass" in n for n in dead_names)

    def test_result_symbols_have_required_fields(self, tmp_path):
        """Each dead symbol should have id, name, kind, file, line, language."""
        _make_indexed_repo(tmp_path)
        result = get_dead_code(
            repo="local/testapp",
            storage_path=str(tmp_path),
        )

        for sym in result["symbols"]:
            assert "id" in sym
            assert "name" in sym
            assert "kind" in sym
            assert "file" in sym
            assert "line" in sym
            assert "language" in sym
