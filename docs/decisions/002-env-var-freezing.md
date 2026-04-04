# ADR-002: Environment Variable Freezing at Import Time

## Status
Accepted

## Context
MCP servers run in-process with dependencies that may be compromised at runtime. If a malicious dependency can mutate `os.environ` after startup, it could toggle security controls off (e.g., disable secret redaction) or redirect API traffic to an attacker-controlled endpoint. Environment variables that control security-sensitive behavior must be captured once and never re-read.

## Decision
Security-sensitive environment variables are read once at module import time and stored in module-level constants. Runtime mutations to `os.environ` are ignored.

**Frozen variables**:

| Variable | Location | Constant | ADV Reference |
|---|---|---|---|
| `CODESIGHT_NO_REDACT` | `src/codesight_mcp/security.py` line 188 | `_NO_REDACT: bool` | ADV-MED-2 |
| `CODE_INDEX_PATH` | `src/codesight_mcp/server.py` line 48 | `_CODE_INDEX_PATH: str` | ADV-LOW-7 |
| `CODESIGHT_ALLOWED_ROOTS` | `src/codesight_mcp/server.py` lines 55-67 | `ALLOWED_ROOTS: list[str]` | ADV-LOW-6, ADV-MED-5 |
| `ANTHROPIC_BASE_URL` | `src/codesight_mcp/summarizer/batch_summarize.py` line 26 | `_ANTHROPIC_BASE_URL: str \| None` | ADV-MED-1 |
| `ANTHROPIC_API_KEY` | `src/codesight_mcp/summarizer/batch_summarize.py` line 30 | `_ANTHROPIC_API_KEY: str` | ADV-MED-5 |

**Additional startup-time validation**:
- `CODESIGHT_ALLOWED_ROOTS` entries that resolve to a filesystem root (`/` or `C:\`) are rejected at startup with a warning (ADV-MED-5, `server.py` lines 60-66).
- `ANTHROPIC_BASE_URL` must use HTTPS if set; non-HTTPS values raise `ValueError` at import time (ADV-MED-6, `batch_summarize.py` lines 35-36).
- `CODESIGHT_NO_REDACT=1` logs a warning at import time so the operator is aware redaction is disabled (`security.py` lines 190-195).

## Consequences
**Positive**: A compromised in-process dependency cannot toggle redaction off, change the storage path, modify allowed roots, redirect API requests, or swap API keys after the server starts.

**Negative**: Changing these variables requires restarting the server process. This is acceptable because these are deployment-time configuration, not runtime controls.
