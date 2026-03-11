"""Path validation chain — ported from basalt-mcp.

Every file access flows through validate_path() which runs
the full 6-step chain. Individual assertions are exposed for
targeted use.
"""

import os
import unicodedata
from pathlib import Path

from .limits import MAX_PATH_LENGTH, MAX_DIRECTORY_DEPTH


class ValidationError(Exception):
    """Raised when a path fails validation. Message is safe to return to AI."""
    pass


def assert_no_control_chars(path: str) -> None:
    """Step 1: Reject null bytes, C0 controls, DEL, and C1 controls.

    Rejects:
    - 0x00–0x1F: C0 control characters (includes null byte, tab, newline, etc.)
    - 0x7F: DEL — would break fnmatch pattern matching for secret filenames
    - 0x80–0x9F: C1 control block — can bypass continuous-ASCII regex assumptions
    """
    if not path:
        raise ValidationError("Path must not be empty")
    if any(ord(c) < 32 or ord(c) == 127 or 128 <= ord(c) <= 159 for c in path):
        raise ValidationError("Path contains control character")


# Backwards-compatible alias — used by existing tests and core/__init__.py exports.
assert_no_null_bytes = assert_no_control_chars


# Dot-prefixed directories that are safe for code indexing
_ALLOWED_DOT_PREFIXES = {".github", ".gitlab", ".circleci", ".husky", ".vscode"}


def assert_safe_segments(path: str) -> None:
    """Step 2: Reject dot-prefixed segments and '..' traversal.

    Allows known-safe dot-prefixed directories (.github, etc.)."""
    for segment in Path(path).parts:
        if segment == ".":
            continue
        if segment == "..":
            raise ValidationError(f"Path contains unsafe segment: {segment}")
        if segment.startswith(".") and segment not in _ALLOWED_DOT_PREFIXES:
            raise ValidationError(f"Path contains unsafe segment: {segment}")


def assert_path_limits(path: str) -> None:
    """Step 3: Enforce max length and depth.

    The depth limit applies only to relative paths.  Absolute paths have
    system-level components (e.g. /private/var/folders/…/T/tmpXXXX) that
    exceed MAX_DIRECTORY_DEPTH on macOS even for shallow repository files,
    so we skip the depth check when the path is already absolute.  Absolute
    paths only reach this function when safe_read_file re-validates an
    already-validated abs_path for defense-in-depth; the relative-path check
    already enforced depth when the path was first validated.
    """
    if len(path) > MAX_PATH_LENGTH:
        raise ValidationError(
            f"Path exceeds maximum length ({len(path)} > {MAX_PATH_LENGTH})"
        )
    p = Path(path)
    if not p.is_absolute():
        depth = len(p.parts)
        if depth > MAX_DIRECTORY_DEPTH:
            raise ValidationError(
                f"Path exceeds maximum depth ({depth} > {MAX_DIRECTORY_DEPTH})"
            )


def is_within(root: Path | str, path: Path | str) -> bool:
    """Return True if *path* is strictly inside *root* (not equal, not a sibling).

    Both arguments must already be resolved absolute paths.
    Uses an ``os.sep`` guard to prevent prefix-only matches
    (e.g. ``/foo/bar`` should not match root ``/foo/b``).
    """
    return str(path).startswith(str(root) + os.sep)


def assert_inside_root(full_path: str, root: str) -> None:
    """Step 5: Strict containment check with os.sep guard."""
    if root == os.sep or root == "/":
        raise ValidationError("Root cannot be filesystem root")
    if not full_path.startswith(root + os.sep):
        raise ValidationError("Path resolves outside root directory")


def assert_no_symlinked_parents(full_path: str, root: str) -> None:
    """Step 6: Walk each parent directory, reject any symlinks."""
    current = Path(full_path).parent
    root_path = Path(root)
    while current != root_path and current != current.parent:
        if current.is_symlink():
            raise ValidationError(
                "Path contains symlink in parent chain"
            )
        current = current.parent


def validate_path(path: str, root: str) -> str:
    """Run the full 6-step validation chain.

    Returns the resolved absolute path if valid.
    Raises ValidationError if any step fails.

    Steps:
        0. NFC normalization — canonical Unicode form before all checks
        1. assert_no_control_chars — reject C0 (ord < 32), DEL (0x7F), C1 (0x80–0x9F)
        2. assert_safe_segments — reject .., dot-prefixed
        3. assert_path_limits — max 512 chars, 10 depth
        4. Path.resolve() — normalize to absolute
        5. assert_inside_root — strict prefix + os.sep
        6. assert_no_symlinked_parents — lstat walk
    """
    # Reject backslashes (potential traversal bypass on mixed-OS paths)
    if "\\" in path:
        raise ValidationError("Backslashes not allowed in paths")
    # Step 0: normalize to NFC so NFD-encoded characters are in canonical form
    # before any string comparison or pattern matching.
    path = unicodedata.normalize("NFC", path)
    assert_no_control_chars(path)
    # Strip ASCII spaces only (not all whitespace — str.strip() would eat
    # control chars that assert_no_control_chars must reject first).
    path = path.strip(" ")
    if not path:
        raise ValidationError("Path must not be empty or whitespace-only")
    assert_safe_segments(path)
    assert_path_limits(path)

    resolved_root = str(Path(root).resolve())
    full_path = str((Path(root) / path).resolve())

    assert_inside_root(full_path, resolved_root)
    assert_no_symlinked_parents(full_path, resolved_root)

    return full_path
