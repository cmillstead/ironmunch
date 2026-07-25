"""README onboarding guards.

Pins the claims docs/spec/SPEC_2_ONBOARDING_AND_DISTRIBUTION.md Section 2 makes
about the primary onboarding path: the Quick Start section must be self
contained (no external repo required) and must document the real console
script entrypoint. If one of these fails, the README drifted from the spec.
"""
import re
from pathlib import Path

README_PATH = Path(__file__).resolve().parents[2] / "README.md"
PYPROJECT_PATH = Path(__file__).resolve().parents[2] / "pyproject.toml"

QUICK_START_HEADING = "## Quick Start"
ADVANCED_HEADING = "### Advanced: single `query` dispatch tool"
ENTRYPOINT_INVOCATION = ".venv/bin/codesight-mcp"
EXTERNAL_REPO_MARKER = "codesight-plugin"
# Non-vacuity guard: these must survive inside the primary path slice, or the
# slice has been emptied/reordered and the checks below it would pass on
# nothing. See docs/spec/SPEC_2_ONBOARDING_AND_DISTRIBUTION.md Section 2.
PRIMARY_PATH_STEP_HEADINGS = ("### Step 1:", "### Step 2:", "### Step 3:")


def _primary_path(readme_text: str) -> str:
    """Return the primary onboarding path: from Quick Start up to (not including) Advanced.

    Both onboarding guard tests must derive their scope from this single helper
    so the definition of "primary path" cannot drift between them. Asserts both
    heading anchors exist, that Advanced comes strictly after Quick Start, and
    that the resulting slice is not vacuous (still contains the numbered Quick
    Start steps) so a moved or emptied section fails loudly instead of passing
    the checks below it by omission.
    """
    quick_start_index = readme_text.find(QUICK_START_HEADING)
    assert quick_start_index != -1, f"heading {QUICK_START_HEADING!r} not found in README.md"

    advanced_index = readme_text.find(ADVANCED_HEADING)
    assert advanced_index != -1, f"heading {ADVANCED_HEADING!r} not found in README.md"

    assert advanced_index > quick_start_index, (
        f"{ADVANCED_HEADING!r} must appear after {QUICK_START_HEADING!r} in README.md"
    )

    primary_path = readme_text[quick_start_index:advanced_index]

    for step_heading in PRIMARY_PATH_STEP_HEADINGS:
        assert step_heading in primary_path, (
            f"{step_heading!r} is missing from the Quick Start primary path (between "
            f"{QUICK_START_HEADING!r} and {ADVANCED_HEADING!r}) — the primary path appears "
            "to be empty or truncated, so downstream onboarding checks would pass vacuously"
        )

    return primary_path


def test_quickstart_has_no_external_repo_in_primary_path():
    readme_text = README_PATH.read_text()
    primary_path = _primary_path(readme_text)
    assert EXTERNAL_REPO_MARKER not in primary_path, (
        f"{EXTERNAL_REPO_MARKER!r} must not appear in the primary Quick Start path "
        f"(between {QUICK_START_HEADING!r} and {ADVANCED_HEADING!r})"
    )


def test_entrypoint_documented():
    readme_text = README_PATH.read_text()
    primary_path = _primary_path(readme_text)
    assert ENTRYPOINT_INVOCATION in primary_path, (
        f"{ENTRYPOINT_INVOCATION!r} must be documented inside the Quick Start primary path"
    )


def test_console_script_exists():
    from codesight_mcp import server

    assert callable(server.main)

    pyproject_text = PYPROJECT_PATH.read_text()
    scripts_index = pyproject_text.find("[project.scripts]")
    assert scripts_index != -1, "[project.scripts] section not found in pyproject.toml"

    next_section_match = re.search(r"^\[", pyproject_text[scripts_index + 1 :], re.MULTILINE)
    scripts_end = (
        scripts_index + 1 + next_section_match.start() if next_section_match else len(pyproject_text)
    )
    scripts_section = pyproject_text[scripts_index:scripts_end]

    assert re.search(
        r'^codesight-mcp\s*=\s*"codesight_mcp\.server:main"\s*$', scripts_section, re.MULTILINE
    ), "pyproject.toml [project.scripts] must declare codesight-mcp = \"codesight_mcp.server:main\""
