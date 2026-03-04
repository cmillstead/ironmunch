"""Tests for storage module."""

import pytest
import json
from pathlib import Path

from ironmunch.storage import IndexStore, CodeIndex
from ironmunch.parser import Symbol


def test_save_and_load_index(tmp_path):
    """Test saving and loading an index."""
    store = IndexStore(base_path=str(tmp_path))

    symbols = [
        Symbol(
            id="test-py::foo",
            file="test.py",
            name="foo",
            qualified_name="foo",
            kind="function",
            language="python",
            signature="def foo():",
            summary="Does foo",
            byte_offset=0,
            byte_length=100,
        )
    ]

    index = store.save_index(
        owner="testowner",
        name="testrepo",
        source_files=["test.py"],
        symbols=symbols,
        raw_files={"test.py": "def foo(): pass"},
        languages={"python": 1}
    )

    assert index.repo == "testowner/testrepo"
    assert len(index.symbols) == 1

    # Load and verify
    loaded = store.load_index("testowner", "testrepo")
    assert loaded is not None
    assert loaded.repo == "testowner/testrepo"
    assert len(loaded.symbols) == 1


def test_byte_offset_content(tmp_path):
    """Test byte-offset content access."""
    store = IndexStore(base_path=str(tmp_path))

    content = "line1\nline2\ndef foo():\n    pass\n"

    symbols = [
        Symbol(
            id="test-py::foo",
            file="test.py",
            name="foo",
            qualified_name="foo",
            kind="function",
            language="python",
            signature="def foo():",
            byte_offset=12,  # Start of "def foo():"
            byte_length=19,  # Length of "def foo():\n    pass"
        )
    ]

    store.save_index(
        owner="testowner",
        name="testrepo",
        source_files=["test.py"],
        symbols=symbols,
        raw_files={"test.py": content},
        languages={"python": 1}
    )

    # Fetch symbol content
    source = store.get_symbol_content("testowner", "testrepo", "test-py::foo")
    assert source is not None
    assert "def foo():" in source


def test_list_repos(tmp_path):
    """Test listing indexed repositories."""
    store = IndexStore(base_path=str(tmp_path))

    # Create two indexes
    for owner, name in [("owner1", "repo1"), ("owner2", "repo2")]:
        store.save_index(
            owner=owner,
            name=name,
            source_files=["main.py"],
            symbols=[],
            raw_files={"main.py": ""},
            languages={"python": 1}
        )

    repos = store.list_repos()
    assert len(repos) == 2


def test_delete_index(tmp_path):
    """Test deleting an index."""
    store = IndexStore(base_path=str(tmp_path))

    store.save_index(
        owner="test",
        name="repo",
        source_files=["main.py"],
        symbols=[],
        raw_files={"main.py": ""},
        languages={"python": 1}
    )

    assert store.load_index("test", "repo") is not None

    store.delete_index("test", "repo")

    assert store.load_index("test", "repo") is None


def test_codeindex_get_symbol():
    """Test getting a symbol by ID from CodeIndex."""
    index = CodeIndex(
        repo="test/repo",
        owner="test",
        name="repo",
        indexed_at="2025-01-15T10:00:00",
        source_files=["main.py"],
        languages={"python": 1},
        symbols=[
            {"id": "main-py::foo", "name": "foo", "kind": "function"},
            {"id": "main-py::bar", "name": "bar", "kind": "function"},
        ]
    )

    sym = index.get_symbol("main-py::foo")
    assert sym is not None
    assert sym["name"] == "foo"

    assert index.get_symbol("nonexistent") is None


def test_codeindex_search():
    """Test searching symbols."""
    index = CodeIndex(
        repo="test/repo",
        owner="test",
        name="repo",
        indexed_at="2025-01-15T10:00:00",
        source_files=["main.py"],
        languages={"python": 1},
        symbols=[
            {"id": "main-py::authenticate", "name": "authenticate", "kind": "function", "signature": "def authenticate(user)", "summary": "Auth user", "keywords": ["auth"]},
            {"id": "main-py::login", "name": "login", "kind": "function", "signature": "def login()", "summary": "Login user", "keywords": []},
            {"id": "main-py::MyClass", "name": "MyClass", "kind": "class", "signature": "class MyClass", "summary": "A class", "keywords": []},
        ]
    )

    # Search by name
    results = index.search("authenticate")
    assert len(results) > 0
    assert results[0]["name"] == "authenticate"

    # Search by kind filter
    results = index.search("login", kind="class")
    assert len(results) == 0  # login is a function

    results = index.search("login", kind="function")
    assert len(results) > 0


def test_get_symbol_docstring_wrapped_as_untrusted(tmp_path):
    """SEC-LOW-7: get_symbol should wrap docstring with wrap_untrusted_content."""
    from ironmunch.parser import Symbol
    from ironmunch.tools.get_symbol import get_symbol

    store = IndexStore(base_path=str(tmp_path))
    content = 'def foo():\n    """This is the docstring."""\n    pass\n'

    symbols = [
        Symbol(
            id="test-py::foo",
            file="test.py",
            name="foo",
            qualified_name="foo",
            kind="function",
            language="python",
            signature="def foo():",
            docstring="This is the docstring.",
            byte_offset=0,
            byte_length=len(content.encode()),
        )
    ]

    store.save_index(
        owner="testowner",
        name="testrepo",
        source_files=["test.py"],
        symbols=symbols,
        raw_files={"test.py": content},
        languages={"python": 1},
    )

    result = get_symbol("testowner/testrepo", "test-py::foo", storage_path=str(tmp_path))

    assert "docstring" in result
    docstring_val = result["docstring"]
    # wrap_untrusted_content adds boundary markers like <<<UNTRUSTED_CODE_...>>>
    assert "UNTRUSTED_CODE" in docstring_val


def test_get_symbol_signature_wrapped_as_untrusted(tmp_path):
    """SEC-MED-2 followup: get_symbol should wrap signature with wrap_untrusted_content."""
    from ironmunch.parser import Symbol
    from ironmunch.tools.get_symbol import get_symbol

    store = IndexStore(base_path=str(tmp_path))
    content = 'def bar(x: int) -> str:\n    pass\n'

    symbols = [
        Symbol(
            id="test-py::bar",
            file="test.py",
            name="bar",
            qualified_name="bar",
            kind="function",
            language="python",
            signature="def bar(x: int) -> str:",
            byte_offset=0,
            byte_length=len(content.encode()),
        )
    ]

    store.save_index(
        owner="testowner",
        name="testrepo",
        source_files=["test.py"],
        symbols=symbols,
        raw_files={"test.py": content},
        languages={"python": 1},
    )

    result = get_symbol("testowner/testrepo", "test-py::bar", storage_path=str(tmp_path))

    assert "signature" in result
    # wrap_untrusted_content adds boundary markers like <<<UNTRUSTED_CODE_...>>>
    assert "UNTRUSTED_CODE" in result["signature"], "signature must contain boundary markers"


def test_get_symbols_signature_wrapped_as_untrusted(tmp_path):
    """SEC-MED-2 followup: get_symbols should wrap signature with wrap_untrusted_content."""
    from ironmunch.parser import Symbol
    from ironmunch.tools.get_symbol import get_symbols

    store = IndexStore(base_path=str(tmp_path))
    content = 'def baz(y: str) -> int:\n    pass\n'

    symbols = [
        Symbol(
            id="test-py::baz",
            file="test.py",
            name="baz",
            qualified_name="baz",
            kind="function",
            language="python",
            signature="def baz(y: str) -> int:",
            byte_offset=0,
            byte_length=len(content.encode()),
        )
    ]

    store.save_index(
        owner="testowner",
        name="testrepo",
        source_files=["test.py"],
        symbols=symbols,
        raw_files={"test.py": content},
        languages={"python": 1},
    )

    result = get_symbols("testowner/testrepo", ["test-py::baz"], storage_path=str(tmp_path))

    assert "symbols" in result
    assert len(result["symbols"]) == 1
    sym = result["symbols"][0]
    # wrap_untrusted_content adds boundary markers like <<<UNTRUSTED_CODE_...>>>
    assert "UNTRUSTED_CODE" in sym["signature"], "signature must contain boundary markers"


def test_get_file_outline_signature_wrapped_as_untrusted(tmp_path):
    """SEC-MED-2: get_file_outline should wrap signature and summary with wrap_untrusted_content."""
    from ironmunch.parser import Symbol
    from ironmunch.tools.get_file_outline import get_file_outline

    store = IndexStore(base_path=str(tmp_path))
    content = 'def bar(x: int) -> str:\n    """Return bar."""\n    return str(x)\n'

    symbols = [
        Symbol(
            id="test-py::bar",
            file="test.py",
            name="bar",
            qualified_name="bar",
            kind="function",
            language="python",
            signature="def bar(x: int) -> str:",
            docstring="Return bar.",
            summary="Converts int to str.",
            byte_offset=0,
            byte_length=len(content.encode()),
        )
    ]

    store.save_index(
        owner="testowner",
        name="testrepo",
        source_files=["test.py"],
        symbols=symbols,
        raw_files={"test.py": content},
        languages={"python": 1},
    )

    result = get_file_outline("testowner/testrepo", "test.py", storage_path=str(tmp_path))

    assert "symbols" in result
    assert len(result["symbols"]) == 1
    sym = result["symbols"][0]

    # SEC-MED-2: signature and summary must be wrapped with boundary markers
    assert "UNTRUSTED_CODE" in sym["signature"], "signature must contain boundary markers"
    assert "UNTRUSTED_CODE" in sym["summary"], "summary must contain boundary markers"


def test_search_symbols_signature_wrapped_as_untrusted(tmp_path):
    """SEC-MED-2: search_symbols should wrap signature and summary with wrap_untrusted_content."""
    from ironmunch.parser import Symbol
    from ironmunch.tools.search_symbols import search_symbols

    store = IndexStore(base_path=str(tmp_path))
    content = 'def baz(y: str) -> int:\n    """Return baz."""\n    return int(y)\n'

    symbols = [
        Symbol(
            id="test-py::baz",
            file="test.py",
            name="baz",
            qualified_name="baz",
            kind="function",
            language="python",
            signature="def baz(y: str) -> int:",
            docstring="Return baz.",
            summary="Converts str to int.",
            byte_offset=0,
            byte_length=len(content.encode()),
        )
    ]

    store.save_index(
        owner="testowner",
        name="testrepo",
        source_files=["test.py"],
        symbols=symbols,
        raw_files={"test.py": content},
        languages={"python": 1},
    )

    result = search_symbols("testowner/testrepo", "baz", storage_path=str(tmp_path))

    assert "results" in result
    assert len(result["results"]) == 1
    sym = result["results"][0]

    # SEC-MED-2: signature and summary must be wrapped with boundary markers
    assert "UNTRUSTED_CODE" in sym["signature"], "signature must contain boundary markers"
    assert "UNTRUSTED_CODE" in sym["summary"], "summary must contain boundary markers"


# ---------------------------------------------------------------------------
# TEST-MED-6: detect_changes() tests
# ---------------------------------------------------------------------------

def test_detect_changes_no_existing_index(tmp_path):
    """With no prior index, all files should be reported as new."""
    store = IndexStore(str(tmp_path))
    changed, new_files, deleted = store.detect_changes("test", "repo", {"main.py": "x=1"})
    assert changed == []
    assert "main.py" in new_files
    assert deleted == []


def test_detect_changes_file_modified(tmp_path):
    """A file whose content changed since last index is reported in changed."""
    store = IndexStore(str(tmp_path))

    # Save an initial index with main.py containing original content
    store.save_index(
        owner="test",
        name="repo",
        source_files=["main.py"],
        symbols=[],
        raw_files={"main.py": "x = 1"},
        languages={"python": 1},
    )

    # Detect with different content for the same file
    changed, new_files, deleted = store.detect_changes("test", "repo", {"main.py": "x = 2"})

    assert "main.py" in changed
    assert new_files == []
    assert deleted == []


def test_detect_changes_file_added(tmp_path):
    """A file not present in the prior index is reported in new_files."""
    store = IndexStore(str(tmp_path))

    # Save an initial index with only main.py
    store.save_index(
        owner="test",
        name="repo",
        source_files=["main.py"],
        symbols=[],
        raw_files={"main.py": "x = 1"},
        languages={"python": 1},
    )

    # Detect with an additional file
    changed, new_files, deleted = store.detect_changes(
        "test", "repo", {"main.py": "x = 1", "utils.py": "def helper(): pass"}
    )

    assert changed == []
    assert "utils.py" in new_files
    assert "main.py" not in new_files
    assert deleted == []


def test_detect_changes_file_deleted(tmp_path):
    """A file present in the prior index but absent from current files is reported as deleted."""
    store = IndexStore(str(tmp_path))

    # Save an initial index with two files
    store.save_index(
        owner="test",
        name="repo",
        source_files=["main.py", "utils.py"],
        symbols=[],
        raw_files={"main.py": "x = 1", "utils.py": "def helper(): pass"},
        languages={"python": 2},
    )

    # Detect with only main.py present (utils.py removed)
    changed, new_files, deleted = store.detect_changes("test", "repo", {"main.py": "x = 1"})

    assert changed == []
    assert new_files == []
    assert "utils.py" in deleted
