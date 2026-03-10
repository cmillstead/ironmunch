"""P3-01: Token efficiency benchmark tests.

Verify that codesight-mcp's structured symbol responses are significantly
more token-efficient than returning raw file content.
"""

import hashlib
import json

import pytest

from codesight_mcp.core.boundaries import wrap_untrusted_content
from codesight_mcp.parser import Symbol
from codesight_mcp.parser.extractor import parse_file
from codesight_mcp.storage import IndexStore


# ---------------------------------------------------------------------------
# Helpers: generate realistic Python source code
# ---------------------------------------------------------------------------


def _make_function(name: str, num_lines: int = 10) -> str:
    """Generate a realistic Python function with docstring and logic."""
    lines = [
        f"def {name}(data: list[dict], threshold: float = 0.5) -> dict:",
        f'    """Process data entries and return aggregated results.',
        f"",
        f"    Iterates over all entries in *data*, applies filtering based on",
        f"    the given *threshold*, and returns a summary dictionary with",
        f"    counts, totals, and per-category breakdowns.",
        f'    """',
        f"    results = {{'count': 0, 'total': 0.0, 'categories': {{}}}}",
    ]
    # Fill body with realistic processing logic
    body_templates = [
        "    for entry in data:",
        "        value = entry.get('value', 0.0)",
        "        category = entry.get('category', 'unknown')",
        "        if value >= threshold:",
        "            results['count'] += 1",
        "            results['total'] += value",
        "            if category not in results['categories']:",
        "                results['categories'][category] = []",
        "            results['categories'][category].append(value)",
        "        else:",
        f"            pass  # Below threshold for {name}",
        "    avg = results['total'] / max(results['count'], 1)",
        "    results['average'] = round(avg, 4)",
        "    results['above_threshold'] = results['count'] > 0",
    ]
    # Repeat body lines to reach desired line count
    while len(lines) < num_lines - 1:
        for tpl in body_templates:
            lines.append(tpl)
            if len(lines) >= num_lines - 1:
                break
    lines.append("    return results")
    return "\n".join(lines) + "\n"


def _make_multi_function_file(num_functions: int, lines_per_fn: int = 15) -> str:
    """Generate a Python file with multiple functions, imports, and constants."""
    header = (
        '"""Auto-generated module for benchmark testing."""\n'
        "\n"
        "import os\n"
        "import sys\n"
        "import json\n"
        "import hashlib\n"
        "from pathlib import Path\n"
        "from typing import Any, Optional\n"
        "\n"
        "MAX_RETRIES = 3\n"
        "DEFAULT_TIMEOUT = 30\n"
        "VERSION = '1.0.0'\n"
        "\n"
    )
    functions = []
    for i in range(num_functions):
        functions.append(_make_function(f"process_batch_{i}", num_lines=lines_per_fn))
    return header + "\n\n".join(functions)


def _index_file(
    tmp_path, file_content: str, filename: str = "module.py"
) -> tuple[IndexStore, list[Symbol]]:
    """Parse a Python file, index it, and return the store and symbols."""
    symbols = parse_file(file_content, filename, "python")
    store = IndexStore(base_path=str(tmp_path))

    raw_files = {filename: file_content}
    # Compute content hashes for each symbol
    content_bytes = file_content.encode("utf-8")
    for sym in symbols:
        chunk = content_bytes[sym.byte_offset : sym.byte_offset + sym.byte_length]
        sym.content_hash = hashlib.sha256(chunk).hexdigest()

    store.save_index(
        owner="local",
        name="benchmark",
        source_files=[filename],
        symbols=symbols,
        raw_files=raw_files,
        languages={"python": 1},
    )
    return store, symbols


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.benchmark
def test_symbol_lookup_smaller_than_full_file(tmp_path):
    """Symbol content for one function should be <20% of a 500+ line file."""
    file_content = _make_multi_function_file(num_functions=20, lines_per_fn=30)
    total_lines = file_content.count("\n")
    assert total_lines >= 500, f"Generated file has only {total_lines} lines"

    store, symbols = _index_file(tmp_path, file_content)
    assert len(symbols) > 0, "No symbols parsed"

    # Pick the first function symbol
    fn_symbols = [s for s in symbols if s.kind == "function"]
    assert len(fn_symbols) > 0, "No function symbols found"
    target = fn_symbols[0]

    symbol_content = store.get_symbol_content("local", "benchmark", target.id)
    assert symbol_content is not None

    file_size = len(file_content.encode("utf-8"))
    symbol_size = len(symbol_content.encode("utf-8"))

    ratio = symbol_size / file_size
    assert ratio < 0.20, (
        f"Symbol content is {ratio:.1%} of file size "
        f"({symbol_size} / {file_size} bytes); expected <20%"
    )


@pytest.mark.benchmark
def test_batch_symbols_vs_full_files(tmp_path):
    """Sum of all symbol contents should be less than the full file.

    The full file includes imports, module docstrings, constants, blank lines
    between functions, etc. that are not part of any single symbol.
    """
    file_content = _make_multi_function_file(num_functions=10, lines_per_fn=20)
    store, symbols = _index_file(tmp_path, file_content)

    fn_symbols = [s for s in symbols if s.kind == "function"]
    assert len(fn_symbols) >= 10, f"Expected >=10 functions, got {len(fn_symbols)}"

    total_symbol_bytes = 0
    for sym in fn_symbols:
        content = store.get_symbol_content("local", "benchmark", sym.id)
        assert content is not None, f"Missing content for {sym.id}"
        total_symbol_bytes += len(content.encode("utf-8"))

    file_size = len(file_content.encode("utf-8"))
    assert total_symbol_bytes < file_size, (
        f"Sum of symbol contents ({total_symbol_bytes} bytes) should be less than "
        f"full file ({file_size} bytes)"
    )


@pytest.mark.benchmark
@pytest.mark.parametrize(
    "content_size",
    [10, 100, 1_000, 10_000],
    ids=["10B", "100B", "1KB", "10KB"],
)
def test_wrapping_overhead_bounded(content_size: int):
    """Boundary marker overhead should be <200 bytes regardless of content size."""
    content = "x" * content_size
    wrapped = wrap_untrusted_content(content)

    overhead = len(wrapped.encode("utf-8")) - len(content.encode("utf-8"))
    assert overhead < 200, (
        f"Wrapping overhead is {overhead} bytes for {content_size}-byte content; "
        f"expected <200 bytes"
    )


@pytest.mark.benchmark
def test_structured_response_vs_raw_dump(tmp_path):
    """A structured symbol response should be smaller than dumping the full file."""
    file_content = _make_multi_function_file(num_functions=15, lines_per_fn=25)
    store, symbols = _index_file(tmp_path, file_content)

    fn_symbols = [s for s in symbols if s.kind == "function"]
    assert len(fn_symbols) > 0
    target = fn_symbols[0]

    symbol_source = store.get_symbol_content("local", "benchmark", target.id)
    assert symbol_source is not None

    # Build a structured response similar to what get_symbol returns
    structured_response = {
        "id": target.id,
        "name": target.name,
        "kind": target.kind,
        "file": target.file,
        "line": target.line,
        "end_line": target.end_line,
        "signature": target.signature,
        "source": symbol_source,
        "_meta": {
            "source": "code_index",
            "contentTrust": "untrusted",
        },
    }

    structured_size = len(json.dumps(structured_response).encode("utf-8"))
    raw_dump_size = len(file_content.encode("utf-8"))

    assert structured_size < raw_dump_size, (
        f"Structured response ({structured_size} bytes) should be smaller than "
        f"raw file dump ({raw_dump_size} bytes)"
    )


@pytest.mark.benchmark
def test_efficiency_scales_with_file_size(tmp_path):
    """Efficiency ratio should improve as file size grows.

    For small files the ratio will be closer to 1.0 (less savings).
    For large files the ratio should be much smaller (more savings).
    """
    sizes = [
        ("small", 3, 10),    # ~30 lines
        ("medium", 8, 15),   # ~120 lines
        ("large", 25, 25),   # ~625 lines
    ]

    ratios = {}
    for label, num_fns, lines_per in sizes:
        # Use separate subdirectories so IndexStores do not collide
        sub = tmp_path / label
        sub.mkdir()

        file_content = _make_multi_function_file(
            num_functions=num_fns, lines_per_fn=lines_per
        )
        store, symbols = _index_file(sub, file_content)

        fn_symbols = [s for s in symbols if s.kind == "function"]
        assert len(fn_symbols) > 0, f"No functions parsed for {label}"

        # Measure first function's content vs full file
        target = fn_symbols[0]
        symbol_content = store.get_symbol_content("local", "benchmark", target.id)
        assert symbol_content is not None

        file_size = len(file_content.encode("utf-8"))
        symbol_size = len(symbol_content.encode("utf-8"))
        ratios[label] = symbol_size / file_size

    # Efficiency should improve (ratio should decrease) as file size grows
    assert ratios["large"] < ratios["small"], (
        f"Efficiency should improve with file size: "
        f"small={ratios['small']:.3f}, medium={ratios['medium']:.3f}, "
        f"large={ratios['large']:.3f}"
    )
    # Large file: single symbol should be <10% of file
    assert ratios["large"] < 0.10, (
        f"Large file ratio {ratios['large']:.3f} should be <0.10"
    )
