"""Tests for path validation chain."""

import os
import tempfile
from pathlib import Path

import pytest

from ironmunch.core.validation import (
    assert_no_null_bytes,
    assert_safe_segments,
    assert_path_limits,
    assert_inside_root,
    assert_no_symlinked_parents,
    validate_path,
    ValidationError,
)


class TestAssertNoNullBytes:
    def test_clean_path(self):
        assert_no_null_bytes("src/main.py")

    def test_null_byte_rejects(self):
        with pytest.raises(ValidationError, match="null byte"):
            assert_no_null_bytes("src/main.py\x00.txt")

    def test_null_in_middle(self):
        with pytest.raises(ValidationError, match="null byte"):
            assert_no_null_bytes("src\x00/../etc/passwd")


class TestAssertSafeSegments:
    def test_clean_path(self):
        assert_safe_segments("src/ironmunch/core/validation.py")

    def test_dot_dot_rejects(self):
        with pytest.raises(ValidationError, match="unsafe segment"):
            assert_safe_segments("src/../../etc/passwd")

    def test_hidden_dir_rejects(self):
        with pytest.raises(ValidationError, match="unsafe segment"):
            assert_safe_segments("src/.git/hooks/pre-commit")

    def test_hidden_file_rejects(self):
        with pytest.raises(ValidationError, match="unsafe segment"):
            assert_safe_segments(".env")

    def test_single_dot_ok(self):
        assert_safe_segments("./src/main.py")

    def test_double_dot_in_name_rejects(self):
        with pytest.raises(ValidationError):
            assert_safe_segments("src/../main.py")


class TestAssertPathLimits:
    def test_normal_path(self):
        assert_path_limits("src/ironmunch/core/validation.py")

    def test_too_long(self):
        long_path = "a/" * 300
        with pytest.raises(ValidationError, match="exceeds maximum length"):
            assert_path_limits(long_path)

    def test_too_deep(self):
        deep_path = "/".join(["dir"] * 15) + "/file.py"
        with pytest.raises(ValidationError, match="exceeds maximum depth"):
            assert_path_limits(deep_path)


class TestAssertInsideRoot:
    def test_inside(self):
        assert_inside_root("/home/user/project/src/main.py", "/home/user/project")

    def test_outside(self):
        with pytest.raises(ValidationError, match="outside root"):
            assert_inside_root("/etc/passwd", "/home/user/project")

    def test_prefix_trick(self):
        """'/root-evil/file' must not pass for root '/root'."""
        with pytest.raises(ValidationError, match="outside root"):
            assert_inside_root("/home/user/project-evil/file.py", "/home/user/project")

    def test_root_itself(self):
        with pytest.raises(ValidationError, match="outside root"):
            assert_inside_root("/home/user/project", "/home/user/project")


class TestAssertNoSymlinkedParents:
    def test_real_dirs(self):
        with tempfile.TemporaryDirectory() as root:
            child = Path(root) / "sub" / "file.txt"
            child.parent.mkdir()
            child.touch()
            assert_no_symlinked_parents(str(child), root)

    def test_symlinked_parent_rejects(self):
        with tempfile.TemporaryDirectory() as root:
            real_dir = Path(root) / "real"
            real_dir.mkdir()
            link_dir = Path(root) / "link"
            link_dir.symlink_to(real_dir)
            target = str(link_dir / "file.txt")
            with pytest.raises(ValidationError, match="symlink"):
                assert_no_symlinked_parents(target, root)


class TestValidatePath:
    """Integration test for the full validation chain."""

    def test_clean_path(self):
        with tempfile.TemporaryDirectory() as root:
            f = Path(root) / "src" / "main.py"
            f.parent.mkdir()
            f.touch()
            result = validate_path("src/main.py", root)
            assert result == str(f.resolve())

    def test_traversal_blocked(self):
        with tempfile.TemporaryDirectory() as root:
            with pytest.raises(ValidationError):
                validate_path("../../etc/passwd", root)

    def test_null_byte_blocked(self):
        with tempfile.TemporaryDirectory() as root:
            with pytest.raises(ValidationError):
                validate_path("file.py\x00.txt", root)
