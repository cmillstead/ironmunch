"""Verify doc counts match running-code values; fail CI on drift."""

import argparse
import re
import subprocess
import sys
from pathlib import Path

from codesight_mcp.parser.languages import LANGUAGE_REGISTRY
from codesight_mcp.tools.registry import load_all_specs

_ROOT = Path(__file__).resolve().parent.parent
_DOCS = [
    "README.md",
    "docs/index.md",
    "docs/project-overview.md",
    "docs/architecture.md",
    "docs/development-guide.md",
    "docs/source-tree-analysis.md",
]
_STALE = ("2,495", "2495", "1,906", "1906")  # known-old test counts
_MARKER = "<!-- codesight:counts ops={ops} langs={langs} tests={tests} -->"
_MARKER_RE = re.compile(r"<!-- codesight:counts[^\n]*-->")
_H1_RE = re.compile(r"(?m)^# .*$")

# Context-anchored patterns for visible counts. The denylist above only
# catches numbers that have gone stale since this script was written; these
# patterns catch a wrong visible number even when it was never on the
# denylist (e.g. the doc was updated to some other incorrect value). Each
# pattern requires the specific trailing/leading unit words so it never
# matches an unrelated integer (fan-in counts, percentages, LOC, etc.).
_TEST_COUNT_PATTERNS = (
    r"tests-(\d[\d,]*)-brightgreen",
    r"\*\*(\d[\d,]*)\s+tests\*\*",
    r"\*\*Tests:\*\*\s*(\d[\d,]*)\s+tests\b",
    r"Test count \| (\d[\d,]*) \|",
    r"\*\*Total\*\*\s*\|\s*\*\*(\d[\d,]*)\*\*",
    r"Run all tests \((\d[\d,]*) tests\)",
    r"Test suite \((\d[\d,]*) tests\)",
)
_OPS_COUNT_PATTERNS = (
    r"(\d+)\s+operations\b",
    r"(\d+)\s+separate tools\b",
    r"(\d+)-tool\b",
    r"(\d+)\s+MCP tools\b",
    r"(\d+)\s+MCP tool implementations\b",
    r"(\d+)\s+tools organized\b",
    r"(\d+)\s+tools with declarative\b",
    r"\((\d+) tools\)",
    r"(\d+)\s+tools for symbol retrieval\b",
)
_LANG_COUNT_PATTERNS = (
    r"(\d+)\s+languages\b",
    r"(\d+)\s+programming languages\b",
    r"(\d+)-language\b",
)


def _test_count() -> int:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        capture_output=True,
        text=True,
        cwd=_ROOT,
    )
    if result.returncode != 0:
        raise SystemExit(f"pytest --collect-only failed (exit {result.returncode}); cannot verify test count")
    match = re.search(r"(\d+)\s+tests?\s+collected", result.stdout)
    if not match:
        raise SystemExit("could not parse collected test count")
    return int(match.group(1))


def _check_visible_counts(rel: str, text: str, patterns: tuple[str, ...], live_value: int, label: str) -> list[str]:
    problems: list[str] = []
    for pattern in patterns:
        for found in re.findall(pattern, text):
            value = int(found.replace(",", ""))
            if value != live_value:
                problems.append(f"{rel}: stale visible {label} count {found!r} (expected {live_value})")
    return problems


def _check_file_text(rel: str, text: str, ops: int, langs: int, tests: int) -> list[str]:
    problems: list[str] = []
    for stale in _STALE:
        if stale in text:
            problems.append(f"{rel}: stale count literal {stale!r}")
    marker = _MARKER.format(ops=ops, langs=langs, tests=tests)
    if marker not in text:
        problems.append(f"{rel}: missing/incorrect generated marker (expected: {marker})")
    problems.extend(_check_visible_counts(rel, text, _TEST_COUNT_PATTERNS, tests, "test"))
    problems.extend(_check_visible_counts(rel, text, _OPS_COUNT_PATTERNS, ops, "operations"))
    problems.extend(_check_visible_counts(rel, text, _LANG_COUNT_PATTERNS, langs, "language"))
    return problems


def _verify_docs(root: Path, docs: list[str], ops: int, langs: int, tests: int) -> list[str]:
    problems: list[str] = []
    for rel in docs:
        text = (root / rel).read_text()
        problems.extend(_check_file_text(rel, text, ops, langs, tests))
    return problems


def _stamp_marker(text: str, marker: str) -> str:
    if _MARKER_RE.search(text):
        return _MARKER_RE.sub(marker, text)
    match = _H1_RE.search(text)
    if match:
        return text[: match.end()] + "\n" + marker + text[match.end() :]
    return marker + "\n" + text


def _format_count(value: int, had_comma: bool) -> str:
    return f"{value:,}" if had_comma else str(value)


def _stamp_pattern(text: str, pattern: str, value: int) -> str:
    regex = re.compile(pattern)

    def _replace(match: re.Match[str]) -> str:
        original = match.group(1)
        replacement = _format_count(value, "," in original)
        full = match.group(0)
        offset = match.start(1) - match.start(0)
        return full[:offset] + replacement + full[offset + len(original) :]

    return regex.sub(_replace, text)


def _stamp_text(text: str, ops: int, langs: int, tests: int) -> str:
    """Stamp `text` with the fresh marker and rewrite every visible count. Pure; no I/O."""
    text = _stamp_marker(text, _MARKER.format(ops=ops, langs=langs, tests=tests))
    for pattern in _TEST_COUNT_PATTERNS:
        text = _stamp_pattern(text, pattern, tests)
    for pattern in _OPS_COUNT_PATTERNS:
        text = _stamp_pattern(text, pattern, ops)
    for pattern in _LANG_COUNT_PATTERNS:
        text = _stamp_pattern(text, pattern, langs)
    return text


def _write_docs(root: Path, docs: list[str], ops: int, langs: int, tests: int) -> None:
    for rel in docs:
        path = root / rel
        path.write_text(_stamp_text(path.read_text(), ops, langs, tests))


def _run(write: bool, root: Path, docs: list[str], ops: int, langs: int, tests: int) -> tuple[int, str]:
    if write:
        _write_docs(root, docs, ops, langs, tests)
    problems = _verify_docs(root, docs, ops, langs, tests)
    if problems:
        return 1, "count drift:\n  " + "\n  ".join(problems)
    return 0, f"counts OK: ops={ops} langs={langs} tests={tests}"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write",
        action="store_true",
        help="Stamp docs with live counts instead of only verifying.",
    )
    return parser.parse_args(argv)


def main() -> int:
    args = _parse_args()
    ops, langs, tests = len(load_all_specs()), len(LANGUAGE_REGISTRY), _test_count()
    code, output = _run(args.write, _ROOT, _DOCS, ops, langs, tests)
    print(output)
    return code


if __name__ == "__main__":
    sys.exit(main())
