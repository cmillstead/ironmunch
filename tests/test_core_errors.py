"""Tests for error sanitization."""

import errno

from ironmunch.core.errors import sanitize_error, strip_system_paths


def test_validation_error_passes_through():
    from ironmunch.core.validation import ValidationError
    err = ValidationError("Path contains null byte")
    msg = sanitize_error(err)
    assert msg == "Path contains null byte"


def test_file_not_found():
    err = FileNotFoundError(errno.ENOENT, "No such file or directory", "/home/user/secret/file.py")
    msg = sanitize_error(err)
    assert "File not found" in msg
    assert "/home/user" not in msg


def test_permission_denied():
    err = PermissionError(errno.EACCES, "Permission denied", "/etc/shadow")
    msg = sanitize_error(err)
    assert "Permission denied" in msg
    assert "/etc/shadow" not in msg


def test_is_a_directory():
    err = IsADirectoryError(errno.EISDIR, "Is a directory", "/home/user/project")
    msg = sanitize_error(err)
    assert "Is a directory" in msg or "directory" in msg.lower()
    assert "/home/user" not in msg


def test_unknown_error_generic_fallback():
    err = RuntimeError("Internal detail: memory at 0xdeadbeef leaked /home/user/secret")
    msg = sanitize_error(err)
    assert msg == "An internal error occurred"
    assert "/home/user" not in msg
    assert "0xdeadbeef" not in msg


def test_oserror_eloop():
    err = OSError(errno.ELOOP, "Too many levels of symbolic links")
    msg = sanitize_error(err)
    assert "symlink" in msg.lower() or "symbolic link" in msg.lower()


def test_path_stripping():
    """System paths must never appear in sanitized output."""
    text = "Error reading /home/user/project/src/main.py: not found"
    stripped = strip_system_paths(text)
    assert "/home/" not in stripped


def test_validation_error_truncated_at_200_chars():
    """SEC-LOW-4: ValidationError messages must be capped at 200 characters."""
    from ironmunch.core.validation import ValidationError
    err = ValidationError("A" * 500)
    msg = sanitize_error(err)
    assert len(msg) <= 200


def test_validation_error_path_stripped():
    """SEC-LOW-14: ValidationError messages must have filesystem paths stripped."""
    from ironmunch.core.errors import sanitize_error
    from ironmunch.core.validation import ValidationError
    err = ValidationError("Not allowed: /Users/cevin/secret-project/config.py")
    msg = sanitize_error(err)
    assert "/Users/cevin" not in msg, f"Path leaked in sanitized error: {msg!r}"
    assert "Not allowed" in msg or len(msg) > 0  # something useful remains
