"""Tests for get_file_tree._build_tree (TEST-MED-1)."""

from collections import Counter
from types import SimpleNamespace

from ironmunch.tools.get_file_tree import _build_tree


def _make_index(files: list[str], symbols: list[dict]) -> object:
    """Return a minimal mock index accepted by _build_tree."""
    return SimpleNamespace(source_files=files, symbols=symbols)


# ---------------------------------------------------------------------------
# 1. Nested structure
# ---------------------------------------------------------------------------

def test_nested_structure():
    """A repo with src/foo/bar.py should produce nested dir/file nodes."""
    index = _make_index(
        files=["src/foo/bar.py"],
        symbols=[],
    )
    tree = _build_tree(["src/foo/bar.py"], index, "")

    # Top level must be a single dir node "src/"
    assert len(tree) == 1
    src_node = tree[0]
    assert src_node["type"] == "dir"
    assert src_node["path"] == "src/"

    # One child: foo/
    assert len(src_node["children"]) == 1
    foo_node = src_node["children"][0]
    assert foo_node["type"] == "dir"
    assert foo_node["path"] == "foo/"

    # One grandchild: bar.py (file)
    assert len(foo_node["children"]) == 1
    bar_node = foo_node["children"][0]
    assert bar_node["type"] == "file"
    assert bar_node["path"] == "src/foo/bar.py"


# ---------------------------------------------------------------------------
# 2. symbol_count on file nodes
# ---------------------------------------------------------------------------

def test_symbol_count():
    """File nodes must carry the correct symbol_count."""
    index = _make_index(
        files=["mod.py"],
        symbols=[
            {"file": "mod.py", "name": "foo", "kind": "function"},
            {"file": "mod.py", "name": "bar", "kind": "function"},
        ],
    )
    tree = _build_tree(["mod.py"], index, "")

    assert len(tree) == 1
    node = tree[0]
    assert node["type"] == "file"
    assert node["path"] == "mod.py"
    assert node["symbol_count"] == 2


def test_symbol_count_zero_for_empty_file():
    """A file with no symbols should have symbol_count == 0."""
    index = _make_index(files=["empty.py"], symbols=[])
    tree = _build_tree(["empty.py"], index, "")

    assert tree[0]["symbol_count"] == 0


# ---------------------------------------------------------------------------
# 3. path_prefix filter
# ---------------------------------------------------------------------------

def test_path_prefix_filter():
    """_build_tree with path_prefix='src/' should only include files under src/."""
    all_files = ["src/a.py", "src/b.py", "lib/c.py"]
    # Caller (get_file_tree) pre-filters by prefix; replicate that here.
    prefix = "src/"
    filtered = [f for f in all_files if f.startswith(prefix)]

    index = _make_index(files=all_files, symbols=[])
    tree = _build_tree(filtered, index, prefix)

    # Tree should contain only a.py and b.py directly (prefix stripped)
    paths = {node["path"] for node in tree}
    assert "src/a.py" in paths
    assert "src/b.py" in paths
    # lib/c.py must NOT appear
    assert not any("lib" in p for p in paths)
