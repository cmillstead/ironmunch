# ADR-004: File-Backed Rate Limiting with Graduated Failure Modes

## Status
Accepted

## Context
MCP tool calls are invoked by AI models which may issue high volumes of requests. Without rate limiting, a misbehaving or manipulated model could exhaust system resources or generate excessive API costs. The rate limiter must persist across server restarts and degrade safely when the filesystem is unavailable.

## Decision
Rate limiting uses a persistent file-backed sliding window, implemented in `src/codesight_mcp/core/rate_limiting.py`. Limits are 60 calls per tool per minute and 300 calls globally per minute (`_MAX_CALLS_PER_MINUTE`, `_MAX_GLOBAL_CALLS_PER_MINUTE`).

**State persistence**: Timestamps are stored as JSON in `.rate_limits.json` within the storage directory, protected by an exclusive file lock (`.rate_limits.lock`). The state file is opened with `O_NOFOLLOW` (ADV-LOW-3, line 107) to prevent symlink-based DoS.

**Graduated failure behavior** (not simple fail-closed):

1. **Unreadable/symlink/corrupt state files**: Treated as empty (`data = {}`), and the request is **allowed through** (lines 108-124). This ensures a corrupt or symlinked state file does not deny service.

2. **Directory creation failures below threshold**: If `_rate_limit_state_dir()` returns `None` (cannot create any state directory), the failure counter increments. While `_consecutive_write_failures < 10`, the request is **allowed through** with a "degraded" warning logged (lines 87-98).

3. **10+ consecutive directory/write failures -- fail-closed**: After `_MAX_WRITE_FAILURES` (10) consecutive `OSError` failures on state directory creation or state file writes, the limiter enters fail-closed mode and **rejects all requests** (lines 70-79). This prevents unlimited unmetered access when the filesystem is persistently broken.

4. **60-second recovery probe** (RC-012): After `_RECOVERY_TIMEOUT_SECONDS` (60 seconds) in fail-closed mode, the next request is allowed through as a probe (lines 80-84). If the subsequent write succeeds, the failure counter resets to zero (line 168) and normal operation resumes. If the write fails again, the counter re-arms and fail-closed continues.

**Thread safety**: The failure counter (`_consecutive_write_failures`) is protected by `_write_failure_lock` (threading.Lock) for safe concurrent access (ADV-LOW-7).

**Predictable-name defense** (TM-5): If the default state directory path is owned by another user (potential pre-creation attack), the limiter retries with a random suffix via `secrets.token_hex(8)` (lines 49-60).

## Consequences
**Positive**: The graduated approach avoids both extremes -- neither permanent denial of service from a single filesystem hiccup, nor unlimited unmetered access when the filesystem is persistently broken. The recovery probe prevents permanent lockout.

**Negative**: During the degraded window (fewer than 10 failures), requests proceed without rate tracking. An attacker who can cause intermittent write failures (but fewer than 10 consecutive) could bypass rate limits. This is an acceptable tradeoff given the 10-failure threshold.
