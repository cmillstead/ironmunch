"""Tests for scripts/check_counts.py --write (stamp) mode. Spec: SPEC_1 §6."""

from pathlib import Path

from scripts.check_counts import _run, _stamp_text


def test_stamp_replaces_marker() -> None:
    # Arrange: a doc with a stale marker, and a doc with no marker at all.
    stale_marker_doc = (
        "# Codesight\n\n"
        "<!-- codesight:counts ops=1 langs=1 tests=1 -->\n\n"
        "Some prose.\n"
    )
    no_marker_doc = "# Codesight\n\nSome prose with no marker yet.\n"

    # Act
    stamped_replace = _stamp_text(stale_marker_doc, ops=42, langs=66, tests=2591)
    stamped_insert = _stamp_text(no_marker_doc, ops=42, langs=66, tests=2591)

    # Assert
    fresh_marker = "<!-- codesight:counts ops=42 langs=66 tests=2591 -->"
    assert stamped_replace.count(fresh_marker) == 1
    assert "ops=1 langs=1 tests=1" not in stamped_replace
    assert stamped_insert.startswith(f"# Codesight\n{fresh_marker}\n")


def test_stamp_rewrites_badge_and_prose_counts() -> None:
    # Arrange
    text = (
        "# Codesight\n\n"
        "![tests](https://img.shields.io/badge/tests-2562-brightgreen)\n\n"
        "**2562 tests**, 34 operations, 66 languages.\n"
    )

    # Act
    stamped = _stamp_text(text, ops=40, langs=68, tests=2600)

    # Assert
    assert "tests-2600-brightgreen" in stamped
    assert "**2600 tests**" in stamped
    assert "40 operations" in stamped
    assert "68 languages" in stamped


def test_stamp_preserves_comma_formatting() -> None:
    # Arrange: prose token has a comma, badge token never does.
    text = (
        "# Codesight\n\n"
        "![tests](https://img.shields.io/badge/tests-2562-brightgreen)\n\n"
        "**2,562 tests** total.\n"
    )

    # Act
    stamped = _stamp_text(text, ops=1, langs=1, tests=9999)

    # Assert
    assert "tests-9999-brightgreen" in stamped  # badge: no comma added
    assert "**9,999 tests**" in stamped  # prose: comma formatting preserved


def test_write_then_verify_is_clean(tmp_path: Path) -> None:
    # Arrange: a fixture doc with drifted counts, written under tmp_path only.
    doc = tmp_path / "fixture.md"
    doc.write_text(
        "# Codesight\n\n"
        "![tests](https://img.shields.io/badge/tests-1-brightgreen)\n\n"
        "**1 tests**, 1 operations, 1 languages.\n"
    )

    # Act
    exit_code, output = _run(
        write=True, root=tmp_path, docs=["fixture.md"], ops=7, langs=8, tests=1234
    )

    # Assert
    assert exit_code == 0
    assert output == "counts OK: ops=7 langs=8 tests=1234"
    stamped = doc.read_text()
    assert "<!-- codesight:counts ops=7 langs=8 tests=1234 -->" in stamped
    assert "tests-1234-brightgreen" in stamped
    assert "**1234 tests**" in stamped
    assert "7 operations" in stamped
    assert "8 languages" in stamped


def test_readonly_mode_unchanged_output(tmp_path: Path) -> None:
    # Arrange: a doc already stamped correctly, and one with drift.
    clean_doc = tmp_path / "clean.md"
    clean_doc.write_text(
        "# Codesight\n\n"
        "<!-- codesight:counts ops=3 langs=4 tests=5 -->\n\n"
        "**5 tests**, 3 operations, 4 languages.\n"
    )
    original_clean_text = clean_doc.read_text()

    drifted_doc = tmp_path / "drifted.md"
    drifted_doc.write_text(
        "# Codesight\n\n"
        "<!-- codesight:counts ops=1 langs=1 tests=1 -->\n\n"
        "**1 tests**.\n"
    )

    # Act: clean doc alone, readonly -> OK and untouched.
    clean_exit, clean_output = _run(
        write=False, root=tmp_path, docs=["clean.md"], ops=3, langs=4, tests=5
    )

    # Act: drifted doc alone, readonly -> drift reported and untouched.
    drift_exit, drift_output = _run(
        write=False, root=tmp_path, docs=["drifted.md"], ops=3, langs=4, tests=5
    )

    # Assert
    assert clean_exit == 0
    assert clean_output == "counts OK: ops=3 langs=4 tests=5"
    assert clean_doc.read_text() == original_clean_text  # readonly never writes

    assert drift_exit == 1
    assert drift_output.startswith("count drift:\n  ")
    assert "missing/incorrect generated marker" in drift_output
    assert drifted_doc.read_text().startswith("# Codesight\n\n<!-- codesight:counts ops=1")
