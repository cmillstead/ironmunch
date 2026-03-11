"""Tests for fuzzing scan findings (FUZZ-1, FUZZ-5, FUZZ-11, FUZZ-19, FUZZ-22).

Scan: docs/plans/2026-03-11-fuzzing-scan.md
"""

import errno
import gzip
import json
import math
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# FUZZ-1: `line` parameter in _INT_PARAM_BOUNDS
# ---------------------------------------------------------------------------
class TestFuzz1LineParamBounds:
    """FUZZ-1: float('inf')/float('nan') for `line` must be coerced/rejected."""

    def test_line_param_inf_coerced(self):
        """float('inf') for line is clamped to upper bound."""
        from codesight_mcp.server import _sanitize_arguments
        result = _sanitize_arguments("get_symbol", {"repo": "owner/repo", "line": float("inf")})
        # Should either clamp or return error string (OverflowError on int(inf))
        if isinstance(result, str):
            assert "line" in result.lower() or "integer" in result.lower()
        else:
            assert result["line"] == 1_000_000

    def test_line_param_nan_rejected(self):
        """float('nan') for line returns error string."""
        from codesight_mcp.server import _sanitize_arguments
        result = _sanitize_arguments("get_symbol", {"repo": "owner/repo", "line": float("nan")})
        # int(nan) raises ValueError, which should be caught
        if isinstance(result, str):
            assert "line" in result.lower() or "integer" in result.lower()
        else:
            # If it somehow passes, it must be a valid bounded int
            assert isinstance(result["line"], int)
            assert 1 <= result["line"] <= 1_000_000

    def test_line_param_negative_clamped(self):
        """Negative line value is clamped to 1."""
        from codesight_mcp.server import _sanitize_arguments
        result = _sanitize_arguments("get_symbol", {"repo": "owner/repo", "line": -1})
        assert isinstance(result, dict)
        assert result["line"] == 1

    def test_line_param_normal_value(self):
        """Normal line value passes through unchanged."""
        from codesight_mcp.server import _sanitize_arguments
        result = _sanitize_arguments("get_symbol", {"repo": "owner/repo", "line": 42})
        assert isinstance(result, dict)
        assert result["line"] == 42

    def test_line_param_zero_clamped_to_min(self):
        """Zero line value is clamped to 1 (lines are 1-indexed)."""
        from codesight_mcp.server import _sanitize_arguments
        result = _sanitize_arguments("get_symbol", {"repo": "owner/repo", "line": 0})
        assert isinstance(result, dict)
        assert result["line"] == 1

    def test_line_param_string_coerced(self):
        """String line value '50' is coerced to int 50."""
        from codesight_mcp.server import _sanitize_arguments
        result = _sanitize_arguments("get_symbol", {"repo": "owner/repo", "line": "50"})
        assert isinstance(result, dict)
        assert result["line"] == 50

    def test_line_in_int_param_bounds(self):
        """Verify 'line' is present in _INT_PARAM_BOUNDS."""
        from codesight_mcp.server import _INT_PARAM_BOUNDS
        assert "line" in _INT_PARAM_BOUNDS
        lo, hi = _INT_PARAM_BOUNDS["line"]
        assert lo == 1
        assert hi == 1_000_000


# ---------------------------------------------------------------------------
# FUZZ-5: BOM (U+FEFF) stripped from paths
# ---------------------------------------------------------------------------
class TestFuzz5BomInPaths:
    """FUZZ-5: BOM character must be stripped from paths during validation."""

    def test_bom_stripped_from_path(self, tmp_path):
        """Path with BOM prefix resolves same as without BOM."""
        from codesight_mcp.core.validation import validate_path

        # Create a real file to validate against
        sub = tmp_path / "src"
        sub.mkdir()
        (sub / "main.py").write_text("pass")

        # Without BOM
        result_clean = validate_path("src/main.py", str(tmp_path))

        # With BOM prefix -- should resolve to the same path
        result_bom = validate_path("\ufeffsrc/main.py", str(tmp_path))
        assert result_bom == result_clean

    def test_bom_in_middle_of_path(self, tmp_path):
        """BOM embedded in path segment is stripped."""
        from codesight_mcp.core.validation import validate_path

        sub = tmp_path / "src"
        sub.mkdir()
        (sub / "main.py").write_text("pass")

        result_clean = validate_path("src/main.py", str(tmp_path))
        result_bom = validate_path("src/\ufeffmain.py", str(tmp_path))
        assert result_bom == result_clean

    def test_multiple_bom_stripped(self, tmp_path):
        """Multiple BOM characters are all removed."""
        from codesight_mcp.core.validation import validate_path

        sub = tmp_path / "src"
        sub.mkdir()
        (sub / "main.py").write_text("pass")

        result_clean = validate_path("src/main.py", str(tmp_path))
        result_bom = validate_path("\ufeff\ufeffsrc/\ufeffmain.py", str(tmp_path))
        assert result_bom == result_clean

    def test_bom_only_path_rejected(self, tmp_path):
        """A path that is only BOM characters becomes empty and is rejected."""
        from codesight_mcp.core.validation import validate_path, ValidationError

        with pytest.raises(ValidationError, match="empty"):
            validate_path("\ufeff", str(tmp_path))


# ---------------------------------------------------------------------------
# FUZZ-11: JSONDecodeError caught in load_index
# ---------------------------------------------------------------------------
class TestFuzz11JsonDecodeError:
    """FUZZ-11: Corrupt JSON in index files must return None, not raise."""

    def test_load_index_corrupt_json_compressed(self, tmp_path):
        """Corrupt JSON inside valid gzip returns None."""
        from codesight_mcp.storage.index_store import IndexStore

        store = IndexStore(base_path=tmp_path)
        # Write corrupt JSON into a gzip file
        index_path = tmp_path / "owner__name.json.gz"
        corrupt_json = b'{"repo": "foo/bar"'  # truncated JSON
        with gzip.open(str(index_path), "wb") as f:
            f.write(corrupt_json)

        result = store.load_index("owner", "name")
        assert result is None

    def test_load_index_corrupt_json_legacy(self, tmp_path):
        """Corrupt JSON in plain (non-gzip) file returns None."""
        from codesight_mcp.storage.index_store import IndexStore

        store = IndexStore(base_path=tmp_path)
        # Write corrupt JSON as plain file (legacy format)
        index_path = tmp_path / "owner__name.json"
        index_path.write_bytes(b'{"repo": INVALID}')

        result = store.load_index("owner", "name")
        assert result is None

    def test_load_index_truncated_json(self, tmp_path):
        """Truncated JSON returns None."""
        from codesight_mcp.storage.index_store import IndexStore

        store = IndexStore(base_path=tmp_path)
        index_path = tmp_path / "owner__name.json.gz"
        truncated = b'[1, 2, '
        with gzip.open(str(index_path), "wb") as f:
            f.write(truncated)

        result = store.load_index("owner", "name")
        assert result is None

    def test_load_index_extra_bytes_after_json(self, tmp_path):
        """Extra bytes after valid JSON returns None (JSONDecodeError on strict parse)."""
        from codesight_mcp.storage.index_store import IndexStore

        store = IndexStore(base_path=tmp_path)
        index_path = tmp_path / "owner__name.json.gz"
        # Valid JSON followed by garbage -- json.loads will raise JSONDecodeError
        bad_data = b'{"repo": "foo/bar"}EXTRA_GARBAGE'
        with gzip.open(str(index_path), "wb") as f:
            f.write(bad_data)

        result = store.load_index("owner", "name")
        assert result is None


# ---------------------------------------------------------------------------
# FUZZ-19: TimeoutError gets specific error message
# ---------------------------------------------------------------------------
class TestFuzz19LockTimeout:
    """FUZZ-19: Lock timeout should return specific, safe error message."""

    def test_sanitize_error_timeout(self):
        """TimeoutError returns a specific message, not generic fallback."""
        from codesight_mcp.core.errors import sanitize_error, GENERIC_FALLBACK

        err = TimeoutError("Could not acquire lock on /some/path within 30s")
        result = sanitize_error(err)
        assert result != GENERIC_FALLBACK
        assert "timed out" in result.lower() or "try again" in result.lower()

    def test_sanitize_error_timeout_no_path_leak(self):
        """TimeoutError message does not leak filesystem paths."""
        from codesight_mcp.core.errors import sanitize_error

        err = TimeoutError("Could not acquire lock on /home/user/.code-index/locks/owner__name.lock within 30s")
        result = sanitize_error(err)
        assert "/home" not in result
        assert ".code-index" not in result
        assert "owner__name" not in result


# ---------------------------------------------------------------------------
# FUZZ-22: Storage directory deletion returns safe error
# ---------------------------------------------------------------------------
class TestFuzz22StorageDeletion:
    """FUZZ-22: Storage directory deletion during operation returns safe error."""

    def test_sanitize_error_enoent(self):
        """OSError with ENOENT returns 'File not found'."""
        from codesight_mcp.core.errors import sanitize_error

        err = OSError(errno.ENOENT, "No such file or directory", "/path/to/file")
        result = sanitize_error(err)
        assert result == "File not found"

    def test_storage_dir_deletion_returns_safe_error(self, tmp_path):
        """Simulated mid-operation directory deletion produces safe error."""
        from codesight_mcp.core.errors import sanitize_error

        # An ENOENT error from a storage operation
        err = OSError(errno.ENOENT, "No such file or directory", str(tmp_path / "content" / "abc123"))
        result = sanitize_error(err)
        assert result == "File not found"
        # Must not contain any path info
        assert str(tmp_path) not in result
