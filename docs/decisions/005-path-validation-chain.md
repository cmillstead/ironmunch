# ADR-005: Path Validation Chain

## Status
Accepted

## Context
Tool handlers accept file paths from AI models, which relay paths from indexed repositories. A malicious path could escape the repository root via traversal (`../`), exploit Unicode normalization differences, or abuse symlinks to reach sensitive files. Every file access must pass a strict multi-step validation chain before any I/O occurs.

## Decision
All file paths are validated through `validate_path()` in `src/codesight_mcp/core/validation.py` (line 109). The chain runs the following steps in order:

**Pre-chain normalization** (before numbered steps):
- **NFC normalization** (line 126): Converts the path to Unicode NFC canonical form so that differently-encoded representations of the same character are unified before any comparison or pattern matching.
- **BOM stripping** (line 129, FUZZ-5): Removes U+FEFF byte order marks. BOMs pass the control-character check (ord > 159) but create invisible path differences on most filesystems.
- **Backslash rejection** (lines 132-133): Rejects any path containing `\` to prevent traversal bypasses on mixed-OS path handling. Applied after NFC normalization to catch backslashes in normalized form.

**Numbered validation steps**:

1. **`assert_no_control_chars()`** (line 134, defined at line 21): Rejects C0 control characters (0x00-0x1F), DEL (0x7F), and C1 controls (0x80-0x9F). DEL would break `fnmatch` pattern matching for secret filenames; C1 controls can bypass continuous-ASCII regex assumptions.

2. **`assert_safe_segments()`** (line 140, defined at line 42): Rejects `..` traversal and dot-prefixed directory segments. A small allowlist (`_ALLOWED_DOT_PREFIXES`: `.github`, `.gitlab`, `.circleci`, `.husky`, `.vscode`) permits known-safe CI/editor directories.

3. **`assert_path_limits()`** (line 141, defined at line 55): Enforces `MAX_PATH_LENGTH` (512 chars) and `MAX_DIRECTORY_DEPTH` (10 levels). Depth is only checked for relative paths -- absolute paths skip the depth check because macOS system paths (e.g., `/private/var/folders/...`) exceed the limit even for shallow files.

4. **`Path.resolve()`** (line 144): Normalizes the path to an absolute form by resolving `.`, `..`, and symlinks. Combined with the root, this produces the canonical filesystem location.

5. **`assert_inside_root()`** (line 146, defined at line 89): Strict containment check using string prefix with `os.sep` guard. Prevents prefix-only matches (e.g., `/foo/bar` must not match root `/foo/b`). Rejects filesystem root as a valid root directory.

6. **`assert_no_symlinked_parents()`** (line 147, defined at line 97): Walks each parent directory from the file up to the root, calling `is_symlink()` on each. Rejects any symlink in the parent chain.

**Post-chain**: Between steps 1 and 2, ASCII spaces are stripped from both ends (line 137). This uses `path.strip(" ")` rather than `str.strip()` to avoid eating control characters that step 1 must reject.

## Consequences
**Positive**: The chain defends against path traversal, Unicode normalization attacks, BOM injection, control character smuggling, symlink escapes, and pathological path lengths. Each step addresses a distinct attack vector, providing defense in depth.

**Negative**: Legitimate files in dot-prefixed directories not on the allowlist (e.g., `.myconfig/`) are rejected. The depth limit of 10 may reject deeply nested files in some monorepo structures. Both are conservative defaults that can be adjusted if needed.
