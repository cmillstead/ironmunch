"""Error sanitization — ported from basalt-mcp.

Never return raw error messages to the AI. ValidationError messages
are pre-approved safe strings. Known errno codes map to safe messages.
Unknown errors get a generic fallback. System paths are always stripped.
"""

import errno
import re
import sys

from .validation import ValidationError


_ERRNO_MESSAGES = {
    errno.ENOENT: "File not found",
    errno.EACCES: "Permission denied",
    errno.EISDIR: "Is a directory, not a file",
    errno.ELOOP: "Too many levels of symbolic links",
    errno.ENAMETOOLONG: "Path name too long",
    errno.ENOSPC: "No space left on device",
    errno.ENOTDIR: "Not a directory",
}

_PATH_PATTERN = re.compile(r"/[\w./-]{2,}")

GENERIC_FALLBACK = "An internal error occurred"


def strip_system_paths(text: str) -> str:
    """Remove filesystem paths from text."""
    return _PATH_PATTERN.sub("<path>", text)


def sanitize_error(err: Exception) -> str:
    """Return a safe error message for the AI.

    - ValidationError: message is pre-approved, pass through.
    - OSError with known errno: return mapped safe message.
    - Everything else: generic fallback.
    """
    if isinstance(err, ValidationError):
        return strip_system_paths(str(err))[:200]

    if isinstance(err, OSError) and err.errno in _ERRNO_MESSAGES:
        return _ERRNO_MESSAGES[err.errno]

    # Log full error to stderr for debugging
    print(f"[ironmunch] Sanitized error: {type(err).__name__}", file=sys.stderr)

    return GENERIC_FALLBACK
