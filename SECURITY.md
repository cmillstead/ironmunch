# Security Model

## Threat Model

codesight-mcp is an MCP server -- it runs locally and exposes tools to a connected AI model. **The connected AI is the attacker.** It can call any tool with any arguments, and it processes untrusted source code that may contain adversarial content designed to manipulate its behavior.

The threat model assumes:

- The AI will attempt path traversal via tool arguments
- The AI will attempt path traversal via poisoned index data
- Source code may contain instructions aimed at the AI (indirect prompt injection)
- Docstrings or summaries may contain injection phrases targeting the host LLM
- Error messages may leak filesystem structure
- Symlinks in indexed directories may point outside the expected root
- Secrets embedded in source code may be exfiltrated if not redacted
- Crafted file/directory names may carry injection content through tool responses

## Defense Matrix

| Threat | Defense |
|--------|---------|
| Path traversal via tool arguments | 6-step validation chain on every path input |
| Path traversal via poisoned index | Validate file paths from index at retrieval time, not just at index time |
| Symlink escape | 3-layer defense: lstat-based filtering during discovery, parent chain walk during validation, `follow_symlinks=False` default, O_NOFOLLOW on all file opens |
| Repository identifier injection | Allowlist pattern (`[a-zA-Z0-9._-]`) with `\Z` anchor and length cap; slashes normalized to `__` |
| Resource exhaustion | Bounded limits on file size, file count, path length, directory depth, search results, index size, batch count, gitignore patterns, and persistent rate limits |
| Information leakage | Error sanitization: ValidationError messages are pre-approved safe strings, known errnos map to safe messages, unknown errors return a generic fallback, system paths stripped, parse failure warnings aggregate counts (not paths) |
| Indirect prompt injection | Content boundary markers with cryptographic random tokens (Microsoft spotlighting) on all untrusted fields; injection phrase detection in summaries; tool descriptions carry explicit warnings |
| Secret exposure in index | Pattern detection at index time: files matching secret patterns excluded; inline secret regex redacts supported token formats from signatures/docstrings/source |
| Secret exposure via control chars | assert_no_control_chars rejects bytes 0x01–0x1F, 0x7F (DEL), and 0x80–0x9F (C1) |
| Binary confusion | Dual-stage detection: extension-based filtering plus null-byte content sniffing |
| Credential logging | _RedactAuthFilter suppresses httpx log records containing auth headers at all log levels |
| Supply chain | `uv.lock` pinned with hashes; CI uses `uv sync --frozen --verify-hashes`; GitHub Actions are SHA-pinned |
| Summarizer injection | Injection phrases stripped from summaries (full substring scan, not prefix-only); degraded-mode parse returns empty on missing nonce delimiters; symbol kind validated against allowlist before prompt interpolation |
| Graph traversal DoS | BFS call-chain capped at 5 paths; all traversal depths clamped to [1, 50]; SHA-256 fingerprint for cache keys |
| Index poisoning | `load_index()` rejects source_files with traversal sequences or control characters |
| Gitignore ReDoS | Per-pattern length cap (200 chars) in both local and GitHub gitignore parsing; pattern count capped at 2000 |
| fd leak on validation failure | `safe_read_file()` transfers fd ownership to fdopen immediately; explicit close on fdopen failure |
| Silent redaction bypass | `CODESIGHT_NO_REDACT=1` logs a warning on first detection |

## Validation Chain

Every file access runs through a 6-step validation chain (`core/validation.py`):

1. **Control character rejection** -- Reject paths containing control bytes (0x01–0x1F, 0x7F, 0x80–0x9F)
2. **Segment safety** -- Reject `..` traversal and dot-prefixed segments (hidden files)
3. **Length and depth limits** -- Max 512 characters, max 10 directory levels
4. **Path resolution** -- `Path.resolve()` to canonical absolute form
5. **Containment check** -- Resolved path must start with `root + os.sep` (strict prefix)
6. **Symlink parent walk** -- `lstat` every parent directory from file up to root; reject any symlinks

Steps 1-3 run on the raw input (before resolution). Steps 4-6 run on the resolved path. This ordering prevents TOCTOU races where resolution could change what steps 1-3 validated.

All file opens use `O_NOFOLLOW` to prevent symlink races at the OS level.

## Resource Limits

All limits are defined in `core/limits.py` and enforced server-side:

| Limit | Value | Purpose |
|-------|-------|---------|
| `MAX_FILE_SIZE` | 500 KB | Prevent memory exhaustion from large files |
| `MAX_FILE_COUNT` | 500 | Cap files per index |
| `MAX_PATH_LENGTH` | 512 chars | Prevent buffer-related issues |
| `MAX_DIRECTORY_DEPTH` | 10 levels | Prevent deeply nested traversal |
| `MAX_CONTEXT_LINES` | 100 lines | Cap context around symbol retrieval |
| `MAX_SEARCH_RESULTS` | 50 results | Bound search output size |
| `MAX_INDEX_SIZE` | 50 MB | Cap stored index JSON |
| `GITHUB_API_TIMEOUT` | 30 seconds | Prevent hanging on GitHub requests |
| `MAX_BATCHES_PER_INDEX` | 50 | Cap AI summarization rounds per index |
| `MAX_GITIGNORE_PATTERNS` | 20 patterns × 200 chars | Prevent regex bomb via extra_ignore_patterns |

## Content Boundaries (Spotlighting)

All untrusted fields returned by tools are individually wrapped in boundary markers with cryptographically random tokens:

```
<<<UNTRUSTED_CODE_a1b2c3d4e5f6...>>>
(source code here)
<<<END_UNTRUSTED_CODE_a1b2c3d4e5f6...>>>
```

Each response uses a fresh 32-character hex token (128 bits of entropy) generated with `secrets.token_hex(16)`. This makes it computationally infeasible for content to forge a matching end marker. This is based on Microsoft's spotlighting research, which reduced successful prompt injection from >50% to <2%.

Every string field from untrusted sources — including `id`, `name`, `file`, `signature`, `summary`, `docstring`, `decorator`, `query`, `context_before`, and `context_after` — is individually wrapped. Tools that return source code also include `_meta` envelopes marking content as untrusted.

## Injection Phrase Detection

Symbol summaries are scanned for injection phrases before storage. Any summary containing phrases like `"ignore"`, `"system:"`, `"IMPORTANT:"`, `"override"`, `"execute"`, and similar is stripped to an empty string. The check uses substring matching (not prefix-only) against the full summary text.

## Secret Detection

### File-level exclusion

Files matching `_SECRET_FILE_PATTERNS` (`.env`, `*_key`, `*.pem`, `id_rsa`, etc.) are excluded from indexing entirely.

### Inline redaction

The `sanitize_signature_for_api()` function applies `_INLINE_SECRET_RE` to signatures, docstrings, and source code. Patterns cover:

- API keys: `sk_live_`, `sk-`, `xoxb-`, `xoxp-`
- Bearer tokens
- AWS keys (`AKIA`), GCP keys (`AIza`), HuggingFace (`hf_`), npm (`npm_`), PyPI (`pypi-`)
- Passwords and credentials in common `key=value` patterns

Matched secrets are replaced with `<REDACTED>`.

`search_text` runs matching against redacted file content, not raw file bytes, requires `confirm_sensitive_search=True`, and rejects queries for the internal redaction marker `<REDACTED>`.

## Rate Limiting

All tools are rate-limited at 60 calls per minute per tool and 300 calls per minute globally. The limits are enforced at the dispatcher level in `server.py` using a persistent file-backed sliding window stored under the index directory, so they survive process restarts. If the default home-directory state path is unavailable, the server falls back to a private per-user temp directory.

## Input Sanitization

`_sanitize_arguments()` in `server.py` enforces:

- String arguments: max 10,000 chars
- `symbol_ids` list: max 50 entries
- Empty query strings: rejected
- Boolean flags: explicitly coerced
- Integer arguments (`max_results`, `context_lines`, `max_results`): clamped to valid ranges
- `byte_offset` / `byte_length`: validated as positive int; `ValidationError` raised on violation

## Storage Security

- Index storage root: `~/.code-index/` (or `CODE_INDEX_PATH`)
- Directory permissions: `0o700` (owner-only access)
- Index writes use 3-phase atomic write: content files first, then JSON `.tmp`, then rename
- `O_NOFOLLOW` on all file reads and writes to prevent symlink races
- `load_index()` validates schema: required fields, type checks, element-level type checks on symbol arrays, source_files path sanitization (rejects traversal sequences and control characters)
- `CODESIGHT_ALLOWED_ROOTS`: colon-separated allowlist; colons within paths are rejected
- Per-repository advisory lock files serialize `save_index()`, `incremental_save()`, and `delete_index()`
- Auxiliary state directories reject symlinks and are forced to `0o700`
- Persistent rate-limit lock/state files use no-follow opens and atomic writes

## Summarizer Security

- Nonces enforced in `_parse_response`: response must begin with `RESP_{nonce}_START` and end with `RESP_{nonce}_END`
- Missing end marker treated as parse failure (empty result), not degraded success
- Missing nonce delimiters entirely: returns empty summaries (no degraded-mode parsing of untrusted text)
- Batch size capped at `MAX_BATCHES_PER_INDEX=50`
- Symbol `kind` validated against `_VALID_KINDS` allowlist before prompt interpolation (prevents kind-injection attacks)
- Injection phrase blocklist expanded: "disregard", "forget", "override", "new instruction" added to existing set
- Signatures sanitized (newlines stripped, length capped) before inclusion in prompts
- `trust_env=False` on both httpx and Anthropic SDK clients

## Security Scan History

| Scan | Date | Findings | Tests |
|------|------|----------|-------|
| Adversarial (initial) | 2026-03-03 | 27 fixed / 4 deferred | +~49 |
| Deep security | 2026-03-03b | 25 fixed | +15 |
| Post-fix review | 2026-03-03c | 13 fixed | +10 |
| Full security review | 2026-03-04 | 16 fixed | +22 |
| Follow-up | 2026-03-04b | 13 fixed | +26 |
| Scan-04c | 2026-03-04c | 13 fixed (1 CRIT) | +14 |
| Scan-04d | 2026-03-04d | 5 MED fixed / 12 LOW deferred | +5 |
| Scan-04e | 2026-03-04e | 16 fixed | +25 |
| Adversarial (2nd round) | 2026-03-04 | 30 fixed | +49 |
| Adversarial (3rd round) | 2026-03-04b | 23 findings (fixes pending) | — |
| Adversarial (4th round) | 2026-03-08 | 18 findings, 11 fixed | pending |
| **Total** | | | **664+ tests** |

## Testing

The test suite contains **664 tests** across adversarial, security, integration, and unit categories covering:

- Control character and DEL byte injection in paths, repo IDs, and queries
- `../` traversal in direct arguments and via poisoned index entries
- Symlink escape (file symlinks, directory symlinks, parent chain symlinks)
- Unicode normalization attacks
- Double-encoding attacks
- Oversized paths and deeply nested paths
- Repository identifier injection (slashes, dots, shell metacharacters, trailing newlines)
- Error message sanitization (no path leakage)
- Content boundary marker integrity and spotlighting on all untrusted fields
- Resource limit enforcement (file size, file count, search results, batch count)
- Secret file detection and inline secret redaction
- Binary file detection
- Atomic write and O_NOFOLLOW enforcement
- Schema validation in load_index
- Rate limit enforcement
- Combined attack vectors

All security-critical tests use real temporary directories and real filesystem operations. No mocking of security-critical code paths.

## Issues Fixed from jcodemunch-mcp

Four security issues were identified in the original jcodemunch-mcp and addressed in codesight-mcp:

1. **Unvalidated file reads at retrieval time** -- jcodemunch validated paths only during indexing. If an index file was modified (or crafted) after indexing, `get_symbol` and `search_text` would read arbitrary files. codesight-mcp validates every file path from the index at retrieval time via `validate_file_access()`.

2. **Unbounded `context_lines` parameter** -- `get_symbol` accepted an arbitrary `context_lines` value, allowing the AI to request the entire file (defeating the purpose of symbol-level retrieval). codesight-mcp clamps `context_lines` to `MAX_CONTEXT_LINES` (100).

3. **Raw error messages exposed to AI** -- Exceptions were returned as-is, potentially leaking filesystem paths, usernames, and internal structure. codesight-mcp sanitizes all errors through `sanitize_error()`, which passes through only pre-approved ValidationError messages or known errno mappings.

4. **No content boundary markers** -- Source code was returned as plain text with no indication that it was untrusted. codesight-mcp wraps all source code and metadata fields in cryptographic boundary markers and includes `_meta` trust envelopes.
