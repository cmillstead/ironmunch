"""Tests for the verify tool -- index health check for CI gates."""

import gzip
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path

from codesight_mcp.parser.symbols import Symbol
from codesight_mcp.storage import IndexStore
from codesight_mcp.tools.verify import verify


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_store_with_repo(tmp_path, symbols=None, raw_files=None):
    """Create an IndexStore with one indexed repo and return (store, index)."""
    if raw_files is None:
        raw_files = {"test.py": "def func():\n    return 1\n"}
    if symbols is None:
        src = raw_files["test.py"]
        symbols = [
            Symbol(
                id="test.py::func#function",
                file="test.py",
                name="func",
                qualified_name="func",
                kind="function",
                language="python",
                signature="def func():",
                summary="A test function",
                byte_offset=0,
                byte_length=len(src.encode("utf-8")),
            ),
        ]
    store = IndexStore(base_path=tmp_path)
    index = store.save_index(
        owner="test",
        name="repo",
        source_files=list(raw_files.keys()),
        symbols=symbols,
        raw_files=raw_files,
        languages={"python": len(raw_files)},
    )
    return store, index


def _set_indexed_at(tmp_path, indexed_at_iso):
    """Overwrite indexed_at in the stored gzip index file."""
    gz_path = Path(tmp_path) / "test__repo.json.gz"
    with gzip.open(gz_path, "rt", encoding="utf-8") as fh:
        data = json.load(fh)
    data["indexed_at"] = indexed_at_iso
    with gzip.open(gz_path, "wt", encoding="utf-8") as fh:
        json.dump(data, fh)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestVerify:
    """Tests for the verify tool."""

    def test_verify_healthy_index(self, tmp_path):
        """A freshly created index should pass all 5 checks."""
        _make_store_with_repo(str(tmp_path))
        result = verify(repo="test/repo", storage_path=str(tmp_path))

        assert result["passed"] is True
        checks = result["checks"]
        assert len(checks) == 5
        for check_name, check in checks.items():
            assert check["passed"] is True, f"Check {check_name} should pass"

    def test_verify_missing_repo(self, tmp_path):
        """Nonexistent repo should return an error dict."""
        result = verify(repo="nonexistent/repo", storage_path=str(tmp_path))
        assert "error" in result

    def test_verify_stale_index(self, tmp_path):
        """An index older than max_age_hours should fail freshness."""
        _make_store_with_repo(str(tmp_path))

        # Overwrite indexed_at to 200 hours ago directly in the gzip file
        old_time = (datetime.now(timezone.utc) - timedelta(hours=200)).isoformat()
        _set_indexed_at(str(tmp_path), old_time)

        result = verify(repo="test/repo", max_age_hours=168, storage_path=str(tmp_path))
        assert result["passed"] is False
        assert result["checks"]["freshness"]["passed"] is False

    def test_verify_empty_index(self, tmp_path):
        """An index with zero symbols should fail the symbols check."""
        _make_store_with_repo(str(tmp_path), symbols=[], raw_files={"test.py": ""})
        result = verify(repo="test/repo", storage_path=str(tmp_path))

        assert result["passed"] is False
        assert result["checks"]["symbols"]["passed"] is False
        assert result["checks"]["symbols"]["count"] == 0

    def test_verify_content_integrity_corrupt(self, tmp_path):
        """When content files are deleted, content_integrity should fail."""
        _make_store_with_repo(str(tmp_path))

        # Delete all content files from the content directory
        content_dir = tmp_path / "test__repo"
        for f in content_dir.rglob("*"):
            if f.is_file() and not f.name.endswith(".json") and not f.name.endswith(".gz"):
                f.unlink()

        result = verify(repo="test/repo", storage_path=str(tmp_path))
        integrity = result["checks"]["content_integrity"]
        assert integrity["passed"] is False
        assert integrity["readable"] < integrity["sampled"]

    def test_verify_deterministic_sampling(self, tmp_path):
        """Sampling should be deterministic -- same symbols selected each time."""
        # Create 10+ symbols
        raw_files = {}
        symbols = []
        for i in range(12):
            fname = f"mod{i}.py"
            src = f"def func{i}():\n    return {i}\n"
            raw_files[fname] = src
            symbols.append(Symbol(
                id=f"{fname}::func{i}#function",
                file=fname,
                name=f"func{i}",
                qualified_name=f"func{i}",
                kind="function",
                language="python",
                signature=f"def func{i}():",
                summary=f"Function {i}",
                byte_offset=0,
                byte_length=len(src.encode("utf-8")),
            ))

        _make_store_with_repo(str(tmp_path), symbols=symbols, raw_files=raw_files)

        result1 = verify(repo="test/repo", storage_path=str(tmp_path))
        result2 = verify(repo="test/repo", storage_path=str(tmp_path))

        ci1 = result1["checks"]["content_integrity"]
        ci2 = result2["checks"]["content_integrity"]
        assert ci1["sampled"] == ci2["sampled"]
        assert ci1["readable"] == ci2["readable"]
        # With 12 symbols, sample should be capped at 5
        assert ci1["sampled"] == 5

    def test_verify_trust_boundary(self, tmp_path):
        """Response must mark content as untrusted with boundary markers."""
        _make_store_with_repo(str(tmp_path))
        result = verify(repo="test/repo", storage_path=str(tmp_path))

        assert result["_meta"]["contentTrust"] == "untrusted"
        assert "<<<UNTRUSTED_CODE_" in result["repo"]

    def test_verify_max_age_hours_param(self, tmp_path):
        """max_age_hours=0 should fail freshness even for a fresh index."""
        _make_store_with_repo(str(tmp_path))
        result = verify(repo="test/repo", max_age_hours=0, storage_path=str(tmp_path))

        assert result["checks"]["freshness"]["passed"] is False

    def test_verify_default_max_age(self, tmp_path):
        """Default max_age_hours should be 168 (1 week)."""
        _make_store_with_repo(str(tmp_path))
        result = verify(repo="test/repo", storage_path=str(tmp_path))

        assert result["checks"]["freshness"]["max_age_hours"] == 168
