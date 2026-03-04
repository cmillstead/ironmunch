"""Shared pytest fixtures for ironmunch tests.

Provides two reusable fixtures to reduce boilerplate in test files:

- ``tmp_index_store``  -- an empty IndexStore backed by a temp directory.
- ``python_index``     -- an IndexStore with one Python file's symbols pre-loaded.
"""

import pytest

from ironmunch.storage import IndexStore
from ironmunch.parser import Symbol


@pytest.fixture
def tmp_index_store(tmp_path):
    """Return an empty IndexStore rooted in a pytest-managed temp directory."""
    return IndexStore(base_path=str(tmp_path))


@pytest.fixture
def python_index(tmp_path):
    """Return an IndexStore with a single Python file's symbols pre-loaded.

    The index is saved under ``local/sample`` with one function symbol
    ``foo`` parsed from ``sample.py``.

    Returns a dict with keys:
        ``store``    -- the IndexStore instance
        ``owner``    -- "local"
        ``name``     -- "sample"
        ``sym_id``   -- the ID of the indexed ``foo`` symbol
        ``src``      -- the raw source string that was indexed
    """
    src = "def foo():\n    return 42\n"

    symbols = [
        Symbol(
            id="sample-py::foo",
            file="sample.py",
            name="foo",
            qualified_name="foo",
            kind="function",
            language="python",
            signature="def foo():",
            summary="Does foo",
            byte_offset=0,
            byte_length=len(src),
        )
    ]

    store = IndexStore(base_path=str(tmp_path))
    store.save_index(
        owner="local",
        name="sample",
        source_files=["sample.py"],
        symbols=symbols,
        raw_files={"sample.py": src},
        languages={"python": 1},
    )

    return {
        "store": store,
        "owner": "local",
        "name": "sample",
        "sym_id": "sample-py::foo",
        "src": src,
    }
