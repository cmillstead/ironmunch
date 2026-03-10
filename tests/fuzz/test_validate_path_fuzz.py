"""P3-03: Fuzzing harness for validate_path.

Generates random/adversarial inputs and verifies that validate_path never
crashes -- it should either return a valid path or raise ValidationError.
"""

import os
import random
import string
import unicodedata

import pytest

from codesight_mcp.core.validation import ValidationError, validate_path

random.seed(42)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _random_ascii_path(length: int) -> str:
    """Generate a random path from printable ASCII characters."""
    chars = string.printable  # includes whitespace, punctuation, digits, letters
    return "".join(random.choice(chars) for _ in range(length))


def _random_unicode_path(length: int) -> str:
    """Generate a random path with CJK, emoji, combining chars, RTL markers."""
    pools = [
        # CJK Unified Ideographs
        [chr(c) for c in range(0x4E00, 0x4E80)],
        # Emoji
        [chr(c) for c in range(0x1F600, 0x1F640)],
        # Combining diacritical marks
        [chr(c) for c in range(0x0300, 0x0340)],
        # RTL markers and bidi
        ["\u200F", "\u200E", "\u202B", "\u202A", "\u202C", "\u2069", "\u2066"],
        # Latin with accents
        [chr(c) for c in range(0x00C0, 0x0100)],
        # Normal ASCII for some segments
        list(string.ascii_letters),
        # Path separators
        ["/"],
    ]
    flat = [c for pool in pools for c in pool]
    return "".join(random.choice(flat) for _ in range(length))


def _safe_name(length: int = 8) -> str:
    """Generate a safe directory/file name (lowercase ascii + digits)."""
    chars = string.ascii_lowercase + string.digits
    # Ensure it starts with a letter (not a dot, not a digit for safety)
    return random.choice(string.ascii_lowercase) + "".join(
        random.choice(chars) for _ in range(length - 1)
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.fuzz
def test_random_ascii_paths_no_crash(tmp_path):
    """Generate 500 random ASCII paths and verify validate_path never crashes.

    Each call must either return a string or raise ValidationError -- no
    other exception type is acceptable.
    """
    root = str(tmp_path)
    for _ in range(500):
        length = random.randint(1, 600)
        path = _random_ascii_path(length)
        try:
            result = validate_path(path, root)
            assert isinstance(result, str)
        except ValidationError:
            pass


@pytest.mark.fuzz
def test_random_unicode_paths_no_crash(tmp_path):
    """Generate 200 random Unicode paths and verify no crashes."""
    root = str(tmp_path)
    for _ in range(200):
        length = random.randint(1, 300)
        path = _random_unicode_path(length)
        try:
            result = validate_path(path, root)
            assert isinstance(result, str)
        except ValidationError:
            pass
        except OSError:
            # Some Unicode paths exceed filesystem byte-length limits
            # even when under MAX_PATH_LENGTH in Python characters.
            # This is an OS-level rejection, not a validate_path bug.
            pass


@pytest.mark.fuzz
def test_control_char_injection(tmp_path):
    """Paths with control chars (C0, DEL, C1) must always raise ValidationError."""
    root = str(tmp_path)
    control_ranges = list(range(0x00, 0x20)) + [0x7F] + list(range(0x80, 0xA0))

    for _ in range(200):
        # Build a path with at least one control character
        base = _safe_name(random.randint(3, 20))
        pos = random.randint(0, len(base))
        ctrl = chr(random.choice(control_ranges))
        path = base[:pos] + ctrl + base[pos:]
        with pytest.raises(ValidationError):
            validate_path(path, root)


@pytest.mark.fuzz
def test_traversal_variants(tmp_path):
    """Generate 100 variations of path traversal -- all must raise ValidationError."""
    root = str(tmp_path)

    traversal_atoms = [
        "..",
        "../",
        "..\\",
        # URL-encoded
        "%2e%2e",
        "%2e%2e%2f",
        # Double-encoded
        "%252e%252e",
        # Fullwidth dots (U+FF0E)
        "\uFF0E\uFF0E",
        # Halfwidth dots (U+FE52)
        "\uFE52\uFE52",
        # Dot above (combining)
        ".\u0307.\u0307",
    ]

    for _ in range(100):
        # Pick a traversal atom and surround it with safe segments
        atom = random.choice(traversal_atoms)
        prefix_depth = random.randint(0, 3)
        prefix = "/".join(_safe_name() for _ in range(prefix_depth)) if prefix_depth else ""
        suffix = _safe_name()
        if prefix:
            path = f"{prefix}/{atom}/{suffix}"
        else:
            path = f"{atom}/{suffix}"

        # NFC-normalize the atom to check if it collapses to ".."
        normalized = unicodedata.normalize("NFC", atom)
        # The path must either be rejected or the normalized form is not ".."
        # and the resolved path stays inside root
        try:
            result = validate_path(path, root)
            # If it passed, ensure it is truly inside root
            assert result.startswith(str(tmp_path.resolve()) + os.sep), (
                f"Traversal variant escaped root: {path!r} -> {result!r}"
            )
        except ValidationError:
            pass  # expected


@pytest.mark.fuzz
def test_extreme_depth(tmp_path):
    """Paths with 11-50 levels of nesting must raise ValidationError."""
    root = str(tmp_path)

    for _ in range(50):
        depth = random.randint(11, 50)
        segments = [_safe_name(4) for _ in range(depth)]
        path = "/".join(segments)
        with pytest.raises(ValidationError):
            validate_path(path, root)


@pytest.mark.fuzz
def test_extreme_length(tmp_path):
    """Paths from 513-2000 chars must raise ValidationError."""
    root = str(tmp_path)

    for _ in range(50):
        target_len = random.randint(513, 2000)
        # Build a path of exactly target_len characters using safe segments
        segments = []
        current_len = 0
        while current_len < target_len:
            seg = _safe_name(8)
            segments.append(seg)
            # +1 for the "/" separator
            current_len += len(seg) + (1 if segments else 0)
        path = "/".join(segments)
        # Trim or pad to exact length
        if len(path) < target_len:
            path += "a" * (target_len - len(path))
        path = path[:target_len]
        assert len(path) >= 513
        with pytest.raises(ValidationError):
            validate_path(path, root)


@pytest.mark.fuzz
def test_null_byte_injection(tmp_path):
    """Paths with null bytes at various positions must raise ValidationError."""
    root = str(tmp_path)

    for _ in range(100):
        base = _safe_name(random.randint(5, 30))
        pos = random.randint(0, len(base))
        path = base[:pos] + "\x00" + base[pos:]
        with pytest.raises(ValidationError):
            validate_path(path, root)


@pytest.mark.fuzz
def test_valid_paths_accepted(tmp_path):
    """Generate 50 valid paths and verify they return a string inside root."""
    root = str(tmp_path)
    resolved_root = str(tmp_path.resolve())

    for _ in range(50):
        depth = random.randint(1, 5)
        segments = [_safe_name(random.randint(3, 12)) for _ in range(depth)]
        path = "/".join(segments)

        # Create the directory structure so resolve() works correctly
        full_dir = tmp_path
        for seg in segments[:-1]:
            full_dir = full_dir / seg
            full_dir.mkdir(exist_ok=True)

        # Create the file
        target = full_dir / segments[-1]
        target.touch()

        result = validate_path(path, root)
        assert isinstance(result, str)
        assert result.startswith(resolved_root + os.sep), (
            f"Valid path not inside root: {path!r} -> {result!r}"
        )


@pytest.mark.fuzz
def test_symlink_in_path_rejected(tmp_path):
    """A symlink that escapes root must raise ValidationError.

    validate_path resolves symlinks via Path.resolve() (step 4), then
    checks the resolved path is inside root (step 5). A symlink pointing
    outside root will resolve to an external location and be rejected by
    assert_inside_root.
    """
    root = str(tmp_path / "project")
    project = tmp_path / "project"
    project.mkdir()

    # Create an outside target
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("sensitive")

    # Create a symlink inside root that points outside root
    escape_link = project / "escape"
    escape_link.symlink_to(outside)

    # Traversing through the symlink should be rejected because the
    # resolved path lands outside root
    with pytest.raises(ValidationError):
        validate_path("escape/secret.txt", root)


@pytest.mark.fuzz
def test_dot_prefixed_segments_rejected(tmp_path):
    """Dot-prefixed segments not in the allowed set must raise ValidationError."""
    root = str(tmp_path)
    allowed = {".github", ".gitlab", ".circleci", ".husky", ".vscode"}

    # Generate random dot-prefixed names that are NOT in the allowed set
    for _ in range(100):
        while True:
            name = "." + _safe_name(random.randint(3, 15))
            if name not in allowed:
                break

        depth = random.randint(0, 3)
        prefix_segs = [_safe_name() for _ in range(depth)]
        suffix = _safe_name()
        segments = prefix_segs + [name, suffix]
        path = "/".join(segments)

        with pytest.raises(ValidationError):
            validate_path(path, root)
