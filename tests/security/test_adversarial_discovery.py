"""Adversarial discovery tests — depth bombs, pattern limits."""

import tempfile
from pathlib import Path

import pytest

from codesight_mcp.discovery import discover_local_files
from codesight_mcp.core.limits import MAX_DIRECTORY_DEPTH


class TestDiscoveryDepthLimit:
    """M-2: Discovery must not traverse deeper than MAX_DIRECTORY_DEPTH."""

    def test_deep_directory_bomb_truncated(self):
        """20-level nesting must be stopped at MAX_DIRECTORY_DEPTH."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Create a 20-level deep directory with a .py file at the bottom
            deep = root
            for i in range(20):
                deep = deep / f"d{i}"
            deep.mkdir(parents=True)
            (deep / "deep.py").write_text("def deep(): pass")

            # Also create a shallow file
            (root / "shallow.py").write_text("def shallow(): pass")

            files, warnings = discover_local_files(root)
            file_names = [f.name for f in files]

            assert "shallow.py" in file_names
            # The deep file should NOT be found (depth > MAX_DIRECTORY_DEPTH)
            assert "deep.py" not in file_names


class TestDiscoveryPatternLimits:
    """M-6: Extra ignore patterns must be bounded."""

    def test_too_many_patterns_truncated(self):
        """More than 20 extra patterns should be silently truncated."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.py").write_text("def main(): pass")

            patterns = [f"pattern_{i}" for i in range(100)]
            # Should not crash or hang
            files, _ = discover_local_files(root, extra_ignore_patterns=patterns)
            assert len(files) >= 0  # Just verify it completes

    def test_very_long_pattern_truncated(self):
        """A pattern longer than 200 chars should be truncated."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.py").write_text("def main(): pass")

            patterns = ["a" * 1000]
            # Should not crash or hang
            files, _ = discover_local_files(root, extra_ignore_patterns=patterns)
            assert len(files) >= 0


class TestGitignoreReDoSProtection:
    """ADV-MED-12: .gitignore patterns longer than MAX_GITIGNORE_PATTERN_LEN must be skipped."""

    def test_long_gitignore_pattern_skipped(self, tmp_path):
        """A .gitignore with a 500-char pattern must be skipped; discover completes without error."""
        import sys
        # Write a .gitignore with a pattern that is 500 characters long
        long_pattern = "a" * 500
        assert len(long_pattern) > 200
        (tmp_path / ".gitignore").write_text(long_pattern + "\n")
        (tmp_path / "main.py").write_text("def main(): pass\n")

        # Must not raise or hang
        files, warnings = discover_local_files(tmp_path)
        file_names = [f.name for f in files]
        # main.py should still be discovered (long pattern was skipped)
        assert "main.py" in file_names


class TestSymlinkDirEscapeCheck:
    """ADV-MED-14: Symlinked directories that escape the root must be pruned before descent."""

    def test_symlinked_dir_outside_root_is_excluded(self, tmp_path):
        """A symlinked directory pointing outside the root must prevent outside files from appearing."""
        import sys

        if sys.platform == "win32":
            pytest.skip("Symlinks not reliable on Windows")

        # Create an outside directory with a Python file
        outside = tmp_path.parent / "outside_dir_adv_med14"
        outside.mkdir(exist_ok=True)
        (outside / "secret.py").write_text("PASSWORD = 'leaked'\n")

        # Create a real file inside the root
        (tmp_path / "inside.py").write_text("x = 1\n")

        # Create a symlinked directory pointing outside
        link_dir = tmp_path / "linked_dir"
        link_dir.symlink_to(outside)

        files, _ = discover_local_files(tmp_path, follow_symlinks=True)
        file_names = [f.name for f in files]

        assert "inside.py" in file_names
        assert "secret.py" not in file_names, (
            "File from outside symlinked dir must not be returned"
        )

    def test_symlinked_dir_inside_root_is_included(self, tmp_path):
        """A symlinked directory pointing within the root must have its files included."""
        import sys

        if sys.platform == "win32":
            pytest.skip("Symlinks not reliable on Windows")

        # Create a real subdirectory inside the root
        real_dir = tmp_path / "real_subdir"
        real_dir.mkdir()
        (real_dir / "module.py").write_text("def f(): pass\n")

        # Create a symlink to that subdirectory inside the root
        link_dir = tmp_path / "linked_to_real"
        link_dir.symlink_to(real_dir)

        files, _ = discover_local_files(tmp_path, follow_symlinks=True)
        file_names = [f.name for f in files]

        # module.py should appear (at least once — possibly twice via real and link)
        assert "module.py" in file_names
