"""P3-05: Large codebase indexing stress tests.

Verify discovery, parsing, and storage handle large codebases correctly.
Uses reduced file counts with adjusted max_files to keep tests fast while
exercising the same logic paths as 5000-file codebases.
"""

import pytest

from pathlib import Path
from codesight_mcp.discovery import discover_local_files
from codesight_mcp.parser import Symbol
from codesight_mcp.parser.extractor import parse_file
from codesight_mcp.storage import IndexStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_symbol(file: str, name: str, kind: str = "function", language: str = "python",
                 byte_offset: int = 0, byte_length: int = 10) -> Symbol:
    """Build a Symbol with sensible defaults."""
    return Symbol(
        id=f"{file}::{name}#{kind}",
        file=file,
        name=name,
        qualified_name=name,
        kind=kind,
        language=language,
        signature=f"def {name}():",
        summary=f"Does {name}",
        byte_offset=byte_offset,
        byte_length=byte_length,
    )


def _populate_dir_with_py_files(root: Path, count: int, subdir: str = "") -> list[Path]:
    """Create `count` .py files under root/subdir, each containing one function.

    Returns the list of created file paths.
    """
    target = root / subdir if subdir else root
    target.mkdir(parents=True, exist_ok=True)
    created = []
    for i in range(count):
        fp = target / f"mod_{i}.py"
        fp.write_text(f"def func_{i}():\n    pass\n")
        created.append(fp)
    return created


def _save_initial_index(store: IndexStore, owner: str, name: str,
                        symbols: list[Symbol], raw_files: dict[str, str],
                        languages: dict[str, int] | None = None):
    """Save an initial index with the given symbols and raw files."""
    source_files = list(raw_files.keys())
    if languages is None:
        languages = {"python": len(source_files)}
    store.save_index(
        owner=owner,
        name=name,
        source_files=source_files,
        symbols=symbols,
        raw_files=raw_files,
        languages=languages,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.stress
class TestDiscoveryLargeCounts:
    """Discovery behaviour at and above the file-count cap."""

    def test_discover_all_files_within_limit(self, tmp_path):
        """Create 100 .py files with max_files=200. All 100 should be returned
        with no truncation warning."""
        _populate_dir_with_py_files(tmp_path, 100)

        files, warnings = discover_local_files(tmp_path, max_files=200)

        assert len(files) == 100
        # No truncation warning
        assert not any("Truncated" in w or "truncat" in w.lower() for w in warnings)

    def test_discover_truncates_above_max(self, tmp_path):
        """Create 60 files with max_files=50. Should return 50 and emit a
        truncation warning. Files in src/ should be preferred."""
        # 30 files in src/ (priority dir), 30 in other/
        _populate_dir_with_py_files(tmp_path, 30, subdir="src")
        _populate_dir_with_py_files(tmp_path, 30, subdir="other")

        files, warnings = discover_local_files(tmp_path, max_files=50)

        assert len(files) == 50
        # Truncation warning emitted
        assert any("Truncated" in w for w in warnings)

        # All 30 src/ files should be in the result (priority)
        src_files = [f for f in files if "src" in str(f)]
        assert len(src_files) == 30

    def test_discover_skips_oversized_files(self, tmp_path):
        """Create 10 files, one being 501KB. Should return 9 files."""
        for i in range(9):
            fp = tmp_path / f"small_{i}.py"
            fp.write_text(f"def func_{i}(): pass\n")

        big = tmp_path / "big.py"
        # 501KB exceeds the default 500KB limit
        big.write_text("x = 1\n" * 100_000)

        files, warnings = discover_local_files(tmp_path)

        # The oversized file should be excluded
        assert len(files) == 9
        filenames = {f.name for f in files}
        assert "big.py" not in filenames


@pytest.mark.stress
class TestParseLargeFile:
    """Parsing a file with many symbols."""

    def test_parse_100_functions(self):
        """A Python file with 100 top-level functions should yield 100 Symbols."""
        lines = []
        for i in range(100):
            lines.append(f"def func_{i}():")
            lines.append(f"    return {i}")
            lines.append("")
        content = "\n".join(lines)

        symbols = parse_file(content, "big_module.py", "python")

        func_symbols = [s for s in symbols if s.kind == "function"]
        assert len(func_symbols) == 100

        # Each function name should appear exactly once
        names = [s.name for s in func_symbols]
        assert len(set(names)) == 100
        for i in range(100):
            assert f"func_{i}" in names


@pytest.mark.stress
class TestStorageLargeIndex:
    """Save and load indices with many symbols."""

    def test_save_and_load_1000_symbols(self, tmp_path):
        """Create 1000 symbols across 100 files, save and load. All must be
        present with correct fields."""
        store = IndexStore(base_path=str(tmp_path))
        owner, name = "stress", "big-repo"

        symbols = []
        raw_files = {}
        source_files = []
        for file_idx in range(100):
            file_path = f"pkg/mod_{file_idx}.py"
            source_files.append(file_path)
            file_funcs = []
            for func_idx in range(10):
                sym_name = f"func_{file_idx}_{func_idx}"
                offset = func_idx * 30
                sym = _make_symbol(file_path, sym_name,
                                   byte_offset=offset, byte_length=25)
                symbols.append(sym)
                file_funcs.append(f"def {sym_name}(): pass")
            raw_files[file_path] = "\n".join(file_funcs) + "\n"

        store.save_index(
            owner=owner,
            name=name,
            source_files=source_files,
            symbols=symbols,
            raw_files=raw_files,
            languages={"python": 100},
        )

        loaded = store.load_index(owner, name)

        assert loaded is not None
        assert len(loaded.symbols) == 1000
        assert len(loaded.source_files) == 100
        assert loaded.languages == {"python": 100}

        # Spot-check a few symbols
        sym_map = {s["id"]: s for s in loaded.symbols}
        for i in [0, 49, 99]:
            sid = f"pkg/mod_{i}.py::func_{i}_0#function"
            assert sid in sym_map
            assert sym_map[sid]["name"] == f"func_{i}_0"
            assert sym_map[sid]["file"] == f"pkg/mod_{i}.py"
            assert sym_map[sid]["kind"] == "function"

    def test_incremental_save_large_changeset(self, tmp_path):
        """Save initial index with 500 symbols. incremental_save with 100
        changed, 50 new, 20 deleted. Final index should have 530 symbols
        (500 - 20 + 50)."""
        store = IndexStore(base_path=str(tmp_path))
        owner, name = "stress", "incr-repo"

        # Initial: 500 symbols in 500 files (1 per file for simplicity)
        initial_symbols = []
        raw_files = {}
        source_files = []
        for i in range(500):
            fp = f"file_{i}.py"
            source_files.append(fp)
            content = f"def func_{i}(): pass"
            raw_files[fp] = content
            initial_symbols.append(_make_symbol(fp, f"func_{i}",
                                                byte_offset=0,
                                                byte_length=len(content)))

        _save_initial_index(store, owner, name, initial_symbols, raw_files)

        # Prepare incremental changes:
        # - Change files 0..99 (100 changed)
        # - Add files 500..549 (50 new)
        # - Delete files 400..419 (20 deleted)
        changed_files = [f"file_{i}.py" for i in range(100)]
        new_files = [f"file_{i}.py" for i in range(500, 550)]
        deleted_files = [f"file_{i}.py" for i in range(400, 420)]

        new_symbols = []
        incr_raw = {}

        # Changed files get updated symbols
        for i in range(100):
            fp = f"file_{i}.py"
            content = f"def func_{i}_v2(): pass"
            incr_raw[fp] = content
            new_symbols.append(_make_symbol(fp, f"func_{i}_v2",
                                            byte_offset=0,
                                            byte_length=len(content)))

        # New files
        for i in range(500, 550):
            fp = f"file_{i}.py"
            content = f"def func_{i}(): pass"
            incr_raw[fp] = content
            new_symbols.append(_make_symbol(fp, f"func_{i}",
                                            byte_offset=0,
                                            byte_length=len(content)))

        updated = store.incremental_save(
            owner=owner,
            name=name,
            changed_files=changed_files,
            new_files=new_files,
            deleted_files=deleted_files,
            new_symbols=new_symbols,
            raw_files=incr_raw,
            languages={"python": 530},
        )

        assert updated is not None
        assert len(updated.symbols) == 530

        sym_names = {s["name"] for s in updated.symbols}

        # Deleted symbols should be gone
        for i in range(400, 420):
            assert f"func_{i}" not in sym_names

        # Changed files should have v2 symbols
        for i in range(100):
            assert f"func_{i}_v2" in sym_names
            assert f"func_{i}" not in sym_names  # old version removed

        # New symbols present
        for i in range(500, 550):
            assert f"func_{i}" in sym_names

        # Unchanged symbols preserved (e.g., 100..399)
        for i in [150, 250, 399]:
            assert f"func_{i}" in sym_names


@pytest.mark.stress
class TestMixedLanguageDiscovery:
    """Discovery should find files across all supported language extensions."""

    def test_discover_7_languages(self, tmp_path):
        """Create files with .py, .js, .go, .rs, .java, .rb, .ts extensions.
        All should be discovered."""
        extensions_and_content = {
            "module.py": "def hello(): pass\n",
            "module.js": "function hello() {}\n",
            "module.go": "package main\nfunc hello() {}\n",
            "module.rs": "fn hello() {}\n",
            "Module.java": "class Module { void hello() {} }\n",
            "module.rb": "def hello; end\n",
            "module.ts": "function hello(): void {}\n",
        }

        for filename, content in extensions_and_content.items():
            (tmp_path / filename).write_text(content)

        files, warnings = discover_local_files(tmp_path)

        found_names = {f.name for f in files}
        for expected in extensions_and_content:
            assert expected in found_names, f"Expected {expected} to be discovered"

        assert len(files) == 7
