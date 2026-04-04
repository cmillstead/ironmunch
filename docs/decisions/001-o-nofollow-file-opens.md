# ADR-001: O_NOFOLLOW on Security-Critical File Operations

## Status
Accepted

## Context
The codesight-mcp index store persists code indexes, metadata, and cached content to disk. An attacker who can create symlinks in the storage directory could redirect reads or writes to arbitrary files (e.g., `/etc/passwd`, `/dev/zero`), enabling data exfiltration, denial of service, or index poisoning. The same risk applies to user-supplied file paths during `safe_read_file` operations.

## Decision
All security-critical file operations use `os.open()` with the `O_NOFOLLOW` flag instead of Python's built-in `open()`. This causes the kernel to reject symlinks at the final path component, returning `ELOOP`. The following functions use `O_NOFOLLOW`:

**Storage layer** (`src/codesight_mcp/storage/index_store.py`):
- `_open_nofollow_text()` (line 94) -- shared helper for reading text files without following symlinks
- `_makedirs_0o700()` (line 129) -- opens directory with `O_NOFOLLOW | O_DIRECTORY` before `fchmod` to avoid TOCTOU race between symlink check and permission change
- `_atomic_write()` (lines 417, 421) -- writes `.tmp` files with `O_NOFOLLOW | O_CREAT | O_TRUNC` before atomic rename
- `save_index()` content writes (line 518) -- per-file content writes during index commit
- `_read_raw_index()` (line 589) -- reads index files with `O_NOFOLLOW`, then uses `fstat` on the open fd to avoid TOCTOU
- `read_source()` (line 833) -- reads symbol source bytes with `O_NOFOLLOW` (SEC-LOW-2)
- `_read_metadata_sidecar()` (line 988) -- reads metadata JSON sidecars
- `list_repos()` scan (line 1068) -- reads index files during repository enumeration
- `_safe_write_content()` (line 1147) -- writes cached content files with `O_NOFOLLOW`

**Security facade** (`src/codesight_mcp/security.py`):
- `safe_read_file()` (line 94) -- the primary file-read entry point for tool handlers

**Other modules**:
- `src/codesight_mcp/core/rate_limiting.py` (line 107) -- rate limit state file reads (ADV-LOW-3)
- `src/codesight_mcp/core/locking.py` (lines 42, 72, 97) -- directory permission enforcement and atomic writes
- `src/codesight_mcp/core/usage_logging.py` (lines 129, 171) -- usage log append and read
- `src/codesight_mcp/discovery.py` (lines 131, 326) -- `.gitignore` reads and binary content sniffing
- `src/codesight_mcp/server.py` (line 485) -- CLI active-status indicator file (F-DA-002)

## Consequences
**Positive**: Symlink-based attacks (TOCTOU, data exfiltration, DoS via `/dev/zero`) are blocked at the kernel level. Combined with `fstat` on open file descriptors, this eliminates the gap between "check" and "use" in file operations.

**Negative**: Legitimate symlinks in storage directories will be rejected. This is intentional -- the storage directory is not expected to contain symlinks. Users who symlink their `CODE_INDEX_PATH` must point to the real directory.
