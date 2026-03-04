"""Functional tests for the index_folder tool (TEST-MED-4)."""

import tempfile
from pathlib import Path

from ironmunch.tools.index_folder import index_folder


def test_no_source_files_returns_no_symbols(tmp_path):
    """A folder with no parseable source files returns an error (no symbols found)."""
    # tmp_path is an allowed root containing only non-parseable content
    result = index_folder(
        path=str(tmp_path),
        use_ai_summaries=False,
        storage_path=str(tmp_path / "_storage"),
        allowed_roots=[str(tmp_path)],
    )

    # The function reports an error when no files are found — success is False
    assert result.get("success") is False
    assert "error" in result


def test_valid_folder_with_python_file(tmp_path):
    """Indexing a folder with one Python file returns success=True with symbols."""
    py_file = tmp_path / "sample.py"
    py_file.write_text(
        "def hello():\n    \"\"\"Say hello.\"\"\"\n    return 'hello'\n"
    )

    result = index_folder(
        path=str(tmp_path),
        use_ai_summaries=False,
        storage_path=str(tmp_path / "_storage"),
        allowed_roots=[str(tmp_path)],
    )

    assert result.get("success") is True, f"Expected success, got: {result}"
    assert result.get("symbol_count", 0) > 0
    assert result.get("file_count", 0) > 0


def test_non_parseable_file_type_still_succeeds_if_py_present(tmp_path):
    """A folder with a non-parseable file type alongside a .py file still succeeds."""
    # Write a parseable Python file
    py_file = tmp_path / "main.py"
    py_file.write_text(
        "def compute(x):\n    \"\"\"Compute something.\"\"\"\n    return x * 2\n"
    )
    # Write a non-parseable file (e.g., .txt)
    txt_file = tmp_path / "notes.txt"
    txt_file.write_text("This is just a text file, not parseable code.\n")

    result = index_folder(
        path=str(tmp_path),
        use_ai_summaries=False,
        storage_path=str(tmp_path / "_storage"),
        allowed_roots=[str(tmp_path)],
    )

    # Should succeed despite having a non-parseable file
    assert result.get("success") is True, f"Expected success, got: {result}"
    # No hard error — just succeeds (warnings may or may not be present)
    assert "error" not in result
