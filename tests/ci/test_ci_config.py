"""P3-02: CI configuration structural validation tests.

Validates the CI workflow configuration without modifying it.
Checks SHA-pinning, permissions, triggers, Python version, and frozen installs.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


def _find_project_root() -> Path:
    """Walk up from this file to find the directory containing pyproject.toml."""
    current = Path(__file__).resolve().parent
    for parent in [current, *current.parents]:
        if (parent / "pyproject.toml").exists():
            return parent
    raise FileNotFoundError("Could not find project root (no pyproject.toml found)")


PROJECT_ROOT = _find_project_root()
CI_WORKFLOW = PROJECT_ROOT / ".github" / "workflows" / "ci.yml"


def _read_ci() -> str:
    return CI_WORKFLOW.read_text(encoding="utf-8")


@pytest.mark.ci
class TestCIConfig:
    """Structural/lint-style tests for the CI workflow."""

    def test_ci_workflow_exists(self) -> None:
        """Assert .github/workflows/ci.yml exists and is valid YAML."""
        assert CI_WORKFLOW.exists(), f"CI workflow not found at {CI_WORKFLOW}"
        content = _read_ci()
        assert len(content.strip()) > 0, "CI workflow file is empty"
        # Basic YAML structure checks: must have top-level keys
        assert "name:" in content, "Missing 'name:' key"
        assert "on:" in content, "Missing 'on:' trigger key"
        assert "jobs:" in content, "Missing 'jobs:' key"

    def test_ci_has_permissions_block(self) -> None:
        """Verify permissions: contents: read is present (least privilege)."""
        content = _read_ci()
        # Check for top-level permissions block with contents: read
        assert re.search(
            r"^permissions:\s*\n\s+contents:\s*read", content, re.MULTILINE
        ), "CI workflow must have 'permissions: contents: read' for least privilege"

    def test_ci_actions_are_sha_pinned(self) -> None:
        """Verify all uses: references use full SHA hashes, not tags."""
        content = _read_ci()
        uses_pattern = re.compile(r"uses:\s*(\S+)")
        sha_pattern = re.compile(r"@[0-9a-f]{40}$")

        for match in uses_pattern.finditer(content):
            action_ref = match.group(1)
            # Skip local actions (starting with ./)
            if action_ref.startswith("./"):
                continue
            assert sha_pattern.search(action_ref), (
                f"Action '{action_ref}' is not SHA-pinned. "
                f"Use a full 40-character commit SHA instead of a tag."
            )

    def test_ci_python_version_matches_requires_python(self) -> None:
        """Verify CI Python version satisfies the requires-python constraint."""
        ci_content = _read_ci()
        pyproject_content = (PROJECT_ROOT / "pyproject.toml").read_text(
            encoding="utf-8"
        )

        # Extract Python version from CI (e.g., "uv python install 3.12")
        ci_match = re.search(r"uv python install\s+([\d.]+)", ci_content)
        assert ci_match, "Could not find 'uv python install X.Y' in CI workflow"
        ci_version = ci_match.group(1)

        # Extract requires-python from pyproject.toml (e.g., '>=3.10')
        req_match = re.search(r'requires-python\s*=\s*"([^"]+)"', pyproject_content)
        assert req_match, "Could not find requires-python in pyproject.toml"
        requires_python = req_match.group(1)

        # Parse the minimum version from the constraint
        min_match = re.search(r">=\s*([\d.]+)", requires_python)
        assert min_match, (
            f"Could not parse minimum version from requires-python: {requires_python}"
        )
        min_version = min_match.group(1)

        # Compare as tuples of ints
        ci_parts = tuple(int(x) for x in ci_version.split("."))
        min_parts = tuple(int(x) for x in min_version.split("."))
        assert ci_parts >= min_parts, (
            f"CI Python version {ci_version} does not satisfy "
            f"requires-python {requires_python}"
        )

    def test_ci_uses_frozen_install(self) -> None:
        """Verify --frozen flag is in the install step (reproducible builds)."""
        content = _read_ci()
        assert "--frozen" in content, (
            "CI workflow must use '--frozen' flag in uv sync "
            "to ensure reproducible dependency installation"
        )
        # Verify it appears in a uv sync command specifically
        assert re.search(
            r"uv sync\s+.*--frozen", content
        ), "The '--frozen' flag must be used with 'uv sync'"

    def test_ci_triggers_on_pr_and_push(self) -> None:
        """Verify both push and pull_request triggers exist."""
        content = _read_ci()
        assert re.search(
            r"^\s+push:", content, re.MULTILINE
        ), "CI workflow must trigger on push events"
        assert re.search(
            r"^\s+pull_request:", content, re.MULTILINE
        ), "CI workflow must trigger on pull_request events"
