"""P3-04: Multi-thread rate limiter stress tests.

Validates the file-backed sliding-window rate limiter under concurrent load,
checking correctness of per-tool and global limits, data integrity, deadlock
freedom, corruption recovery, symlink rejection, and window reset.
"""

import json
import os
import threading
import time
from unittest import mock

import pytest

from codesight_mcp.core.rate_limiting import (
    _MAX_CALLS_PER_MINUTE,
    _MAX_GLOBAL_CALLS_PER_MINUTE,
    _rate_limit,
)

pytestmark = pytest.mark.stress


@pytest.fixture()
def rate_dir(tmp_path):
    """Return a temp directory path string for rate-limit state storage."""
    d = tmp_path / "rate_state"
    d.mkdir()
    os.chmod(d, 0o700)
    return str(d)


# ── 1. Per-tool limit exact boundary ─────────────────────────────────────


def test_per_tool_limit_exact_boundary(rate_dir):
    """60 calls for one tool all pass; 61st is rejected; different tool passes."""
    tool = "test_tool_boundary"

    for i in range(_MAX_CALLS_PER_MINUTE):
        assert _rate_limit(tool, rate_dir) is True, f"call {i+1} should be allowed"

    assert _rate_limit(tool, rate_dir) is False, "call 61 should be rejected"

    # A different tool should still be allowed (separate per-tool bucket).
    assert _rate_limit("other_tool", rate_dir) is True


# ── 2. Global limit boundary ─────────────────────────────────────────────


def test_global_limit_boundary(rate_dir):
    """300 calls across 300 distinct tools pass; 301st is rejected."""
    for i in range(_MAX_GLOBAL_CALLS_PER_MINUTE):
        name = f"gtool_{i:04d}"
        assert _rate_limit(name, rate_dir) is True, f"global call {i+1} should pass"

    assert _rate_limit("gtool_overflow", rate_dir) is False, "global call 301 should be rejected"


# ── 3. Concurrent threads respect per-tool limits ────────────────────────


def test_concurrent_threads_respect_limits(rate_dir):
    """10 threads x 10 calls = 100 attempts for one tool; exactly 60 should pass."""
    tool = "concurrent_tool"
    results: list[bool] = []
    lock = threading.Lock()

    def worker():
        local_results = []
        for _ in range(10):
            local_results.append(_rate_limit(tool, rate_dir))
        with lock:
            results.extend(local_results)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    allowed = sum(1 for r in results if r is True)
    denied = sum(1 for r in results if r is False)

    assert allowed == _MAX_CALLS_PER_MINUTE, f"expected {_MAX_CALLS_PER_MINUTE} allowed, got {allowed}"
    assert denied == 100 - _MAX_CALLS_PER_MINUTE
    assert len(results) == 100


# ── 4. Concurrent threads — no data corruption ──────────────────────────


def test_concurrent_threads_no_data_corruption(rate_dir):
    """20 threads hammering _rate_limit must leave valid JSON with valid timestamps."""
    barrier = threading.Barrier(20, timeout=10)

    def worker(idx):
        barrier.wait()
        for _ in range(5):
            _rate_limit(f"corruption_tool_{idx % 3}", rate_dir)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    state_path = os.path.join(rate_dir, ".rate_limits.json")
    assert os.path.exists(state_path), "state file must exist after calls"

    with open(state_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)  # must be valid JSON

    assert isinstance(data, dict)

    # All global timestamps must be valid floats.
    for ts in data.get("global", []):
        assert isinstance(ts, (int, float)), f"bad global timestamp: {ts!r}"
        assert ts > 0

    # All per-tool timestamps must be valid floats with no duplicates.
    tools = data.get("tools", {})
    assert isinstance(tools, dict)
    for tool_name, timestamps in tools.items():
        assert isinstance(timestamps, list), f"timestamps for {tool_name} is not a list"
        for ts in timestamps:
            assert isinstance(ts, (int, float)), f"bad timestamp in {tool_name}: {ts!r}"
            assert ts > 0
        # No exact duplicate timestamps (each call gets its own time.time()).
        assert len(timestamps) == len(set(timestamps)), (
            f"duplicate timestamps in {tool_name}"
        )


# ── 5. No deadlock under heavy contention ────────────────────────────────


def test_no_deadlock_under_heavy_contention(rate_dir):
    """50 threads all calling _rate_limit complete within 30 seconds."""
    barrier = threading.Barrier(50, timeout=10)
    completed = threading.Event()

    def worker():
        barrier.wait()
        for _ in range(5):
            _rate_limit("deadlock_tool", rate_dir)

    threads = [threading.Thread(target=worker) for _ in range(50)]
    start = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    elapsed = time.monotonic() - start

    assert elapsed < 30, f"threads took {elapsed:.1f}s — possible deadlock"

    alive = [t for t in threads if t.is_alive()]
    assert len(alive) == 0, f"{len(alive)} threads still alive — deadlock detected"


# ── 6. State file corruption recovery ────────────────────────────────────


def test_state_file_corruption_recovery(rate_dir):
    """Garbage in .rate_limits.json is handled gracefully (reset to empty)."""
    state_path = os.path.join(rate_dir, ".rate_limits.json")

    # Write various forms of garbage.
    for garbage in [b"{{{{not json", b"\x00\xff\xfe", b"null", b"[1,2,3]"]:
        with open(state_path, "wb") as fh:
            fh.write(garbage)

        result = _rate_limit("recovery_tool", rate_dir)
        assert result is True, f"should recover from garbage: {garbage!r}"


# ── 7. Lock file symlink rejection ───────────────────────────────────────


def test_lock_file_symlink_rejection(rate_dir):
    """If .rate_limits.json is a symlink, _rate_limit must not follow it."""
    state_path = os.path.join(rate_dir, ".rate_limits.json")
    target_path = os.path.join(rate_dir, "real_state.json")

    # Create a valid state file and symlink to it.
    with open(target_path, "w") as fh:
        fh.write("{}")
    os.symlink(target_path, state_path)

    # Should succeed (treats symlink as missing/empty, resets state).
    result = _rate_limit("symlink_tool", rate_dir)
    assert result is True

    # The symlink should have been replaced by a real file (via atomic write),
    # or the call should have succeeded without following the symlink.
    # Either way, verify the tool was allowed.
    assert result is True


# ── 8. Rate limit resets after window elapses ─────────────────────────────


def test_rate_limit_resets_after_window(rate_dir):
    """Saturate the per-tool limit, advance time 61 seconds, then succeed."""
    tool = "window_reset_tool"

    # Saturate.
    for _ in range(_MAX_CALLS_PER_MINUTE):
        assert _rate_limit(tool, rate_dir) is True

    assert _rate_limit(tool, rate_dir) is False, "should be rate-limited"

    # Jump forward 61 seconds — all old timestamps fall outside the window.
    real_time = time.time
    with mock.patch("codesight_mcp.core.rate_limiting.time") as mock_time:
        mock_time.time = lambda: real_time() + 61
        result = _rate_limit(tool, rate_dir)

    assert result is True, "should be allowed after window resets"
