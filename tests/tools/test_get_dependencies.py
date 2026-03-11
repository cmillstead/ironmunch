"""Tests for get_dependencies tool."""

import hashlib

import pytest

from codesight_mcp.tools.get_dependencies import get_dependencies
from codesight_mcp.storage import IndexStore
from codesight_mcp.parser import Symbol


def _make_src_hash(src: str) -> str:
    return hashlib.sha256(src.encode("utf-8")).hexdigest()


def _make_indexed_repo(tmp_path):
    """Create an index with symbols that have both internal and external imports.

    Layout:
        app.py        -- imports flask, os, utils (internal)
        utils.py      -- imports re, sqlalchemy
        models.py     -- imports flask, sqlalchemy, utils (internal)
    """
    app_src = "from flask import Flask\nimport os\nfrom utils import helper\n"
    utils_src = "import re\nfrom sqlalchemy import Column\n"
    models_src = "from flask import db\nfrom sqlalchemy import Model\nfrom utils import Base\n"

    symbols = [
        Symbol(
            id="app.py::main#function",
            file="app.py",
            name="main",
            qualified_name="main",
            kind="function",
            language="python",
            signature="def main():",
            line=1, end_line=5,
            byte_offset=0, byte_length=len(app_src),
            content_hash=_make_src_hash(app_src),
            imports=["flask", "os", "utils"],
        ),
        Symbol(
            id="utils.py::helper#function",
            file="utils.py",
            name="helper",
            qualified_name="helper",
            kind="function",
            language="python",
            signature="def helper():",
            line=1, end_line=3,
            byte_offset=0, byte_length=len(utils_src),
            content_hash=_make_src_hash(utils_src),
            imports=["re", "sqlalchemy"],
        ),
        Symbol(
            id="models.py::MyModel#class",
            file="models.py",
            name="MyModel",
            qualified_name="MyModel",
            kind="class",
            language="python",
            signature="class MyModel:",
            line=1, end_line=4,
            byte_offset=0, byte_length=len(models_src),
            content_hash=_make_src_hash(models_src),
            imports=["flask", "sqlalchemy", "utils"],
        ),
    ]

    store = IndexStore(base_path=str(tmp_path))
    content_dir = tmp_path / "local__testapp"
    content_dir.mkdir(parents=True, exist_ok=True)
    (content_dir / "app.py").write_text(app_src)
    (content_dir / "utils.py").write_text(utils_src)
    (content_dir / "models.py").write_text(models_src)

    store.save_index(
        owner="local",
        name="testapp",
        source_files=["app.py", "utils.py", "models.py"],
        symbols=symbols,
        raw_files={
            "app.py": app_src,
            "utils.py": utils_src,
            "models.py": models_src,
        },
        languages={"python": 3},
    )
    return store


class TestGetDependenciesExternal:
    """Tests that external imports are identified correctly."""

    def test_identifies_external_imports(self, tmp_path):
        _make_indexed_repo(tmp_path)
        result = get_dependencies("local/testapp", storage_path=str(tmp_path))
        assert "error" not in result
        external_modules = [e["module"] for e in result["external"]]
        # flatten wrapped content
        external_names = [m.split("\n")[1] for m in external_modules]
        assert "flask" in external_names
        assert "sqlalchemy" in external_names
        assert "os" in external_names
        assert "re" in external_names

    def test_external_import_count(self, tmp_path):
        _make_indexed_repo(tmp_path)
        result = get_dependencies("local/testapp", storage_path=str(tmp_path))
        # flask is imported by app.py and models.py => count 2
        flask_entry = next(
            e for e in result["external"]
            if "flask" in e["module"]
        )
        assert flask_entry["import_count"] == 2

    def test_external_shows_importing_files(self, tmp_path):
        _make_indexed_repo(tmp_path)
        result = get_dependencies("local/testapp", storage_path=str(tmp_path))
        flask_entry = next(
            e for e in result["external"]
            if "flask" in e["module"]
        )
        imported_by_raw = [f.split("\n")[1] for f in flask_entry["imported_by"]]
        assert "app.py" in imported_by_raw
        assert "models.py" in imported_by_raw

    def test_sorted_by_import_count_descending(self, tmp_path):
        _make_indexed_repo(tmp_path)
        result = get_dependencies("local/testapp", storage_path=str(tmp_path))
        counts = [e["import_count"] for e in result["external"]]
        assert counts == sorted(counts, reverse=True)


class TestGetDependenciesInternal:
    """Tests that internal imports are identified correctly."""

    def test_identifies_internal_imports(self, tmp_path):
        _make_indexed_repo(tmp_path)
        result = get_dependencies("local/testapp", storage_path=str(tmp_path))
        assert "error" not in result
        internal_modules = [e["module"] for e in result["internal"]]
        internal_names = [m.split("\n")[1] for m in internal_modules]
        # utils matches utils.py (stem "utils")
        assert "utils" in internal_names

    def test_internal_not_in_external(self, tmp_path):
        _make_indexed_repo(tmp_path)
        result = get_dependencies("local/testapp", storage_path=str(tmp_path))
        external_names = [e["module"].split("\n")[1] for e in result["external"]]
        internal_names = [e["module"].split("\n")[1] for e in result["internal"]]
        # No overlap
        assert not set(external_names) & set(internal_names)

    def test_internal_import_count(self, tmp_path):
        _make_indexed_repo(tmp_path)
        result = get_dependencies("local/testapp", storage_path=str(tmp_path))
        # utils is imported by app.py and models.py => count 2
        utils_entry = next(
            e for e in result["internal"]
            if "utils" in e["module"]
        )
        assert utils_entry["import_count"] == 2


class TestGetDependenciesErrors:
    """Tests for error handling."""

    def test_repo_not_found_returns_error(self, tmp_path):
        result = get_dependencies("local/nonexistent", storage_path=str(tmp_path))
        assert "error" in result

    def test_bare_repo_not_found_returns_error(self, tmp_path):
        result = get_dependencies("nonexistent", storage_path=str(tmp_path))
        assert "error" in result


class TestGetDependenciesMeta:
    """Tests for _meta envelope."""

    def test_has_meta_with_timing_ms(self, tmp_path):
        _make_indexed_repo(tmp_path)
        result = get_dependencies("local/testapp", storage_path=str(tmp_path))
        assert "_meta" in result
        assert "timing_ms" in result["_meta"]
        assert isinstance(result["_meta"]["timing_ms"], float)

    def test_meta_has_counts(self, tmp_path):
        _make_indexed_repo(tmp_path)
        result = get_dependencies("local/testapp", storage_path=str(tmp_path))
        meta = result["_meta"]
        assert "external_count" in meta
        assert "internal_count" in meta
        assert meta["external_count"] == len(result["external"])
        assert meta["internal_count"] == len(result["internal"])

    def test_meta_content_trust_is_trusted(self, tmp_path):
        _make_indexed_repo(tmp_path)
        result = get_dependencies("local/testapp", storage_path=str(tmp_path))
        assert result["_meta"]["contentTrust"] == "trusted"

    def test_result_has_repo_field(self, tmp_path):
        _make_indexed_repo(tmp_path)
        result = get_dependencies("local/testapp", storage_path=str(tmp_path))
        assert result["repo"] == "local/testapp"


class TestGetDependenciesEdgeCases:
    """Edge case tests."""

    def test_no_imports_returns_empty_lists(self, tmp_path):
        """Symbols with no imports should produce empty external and internal lists."""
        src = "def noop(): pass\n"
        symbols = [
            Symbol(
                id="noop.py::noop#function",
                file="noop.py",
                name="noop",
                qualified_name="noop",
                kind="function",
                language="python",
                signature="def noop():",
                line=1, end_line=1,
                byte_offset=0, byte_length=len(src),
                content_hash=hashlib.sha256(src.encode()).hexdigest(),
                imports=[],
            )
        ]
        store = IndexStore(base_path=str(tmp_path))
        content_dir = tmp_path / "local__emptyrepo"
        content_dir.mkdir(parents=True, exist_ok=True)
        (content_dir / "noop.py").write_text(src)
        store.save_index(
            owner="local",
            name="emptyrepo",
            source_files=["noop.py"],
            symbols=symbols,
            raw_files={"noop.py": src},
            languages={"python": 1},
        )

        result = get_dependencies("local/emptyrepo", storage_path=str(tmp_path))
        assert result["external"] == []
        assert result["internal"] == []
        assert result["_meta"]["external_count"] == 0
        assert result["_meta"]["internal_count"] == 0

    def test_duplicate_imports_across_symbols_deduped_per_file(self, tmp_path):
        """Same module imported by two symbols in same file counts once for that file."""
        src = "import os\nimport os\n"
        symbols = [
            Symbol(
                id="dup.py::a#function",
                file="dup.py",
                name="a",
                qualified_name="a",
                kind="function",
                language="python",
                signature="def a():",
                line=1, end_line=1,
                byte_offset=0, byte_length=len(src),
                content_hash=hashlib.sha256(src.encode()).hexdigest(),
                imports=["os"],
            ),
            Symbol(
                id="dup.py::b#function",
                file="dup.py",
                name="b",
                qualified_name="b",
                kind="function",
                language="python",
                signature="def b():",
                line=2, end_line=2,
                byte_offset=0, byte_length=len(src),
                content_hash=hashlib.sha256(src.encode()).hexdigest(),
                imports=["os"],
            ),
        ]
        store = IndexStore(base_path=str(tmp_path))
        content_dir = tmp_path / "local__duprepo"
        content_dir.mkdir(parents=True, exist_ok=True)
        (content_dir / "dup.py").write_text(src)
        store.save_index(
            owner="local",
            name="duprepo",
            source_files=["dup.py"],
            symbols=symbols,
            raw_files={"dup.py": src},
            languages={"python": 1},
        )

        result = get_dependencies("local/duprepo", storage_path=str(tmp_path))
        os_entry = next(
            e for e in result["external"]
            if "os" in e["module"]
        )
        # dup.py imports os, but it's only one file
        assert os_entry["import_count"] == 1
        assert len(os_entry["imported_by"]) == 1
