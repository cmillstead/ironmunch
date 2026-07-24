"""Spec-constant guard tests.

Pins the values that docs/spec/SPEC_1_BASELINE_AND_SCAFFOLD.md declares as
Key Constants. If one of these fails, the code drifted from the spec (or
the spec changed and this test needs a matching update) -- either way it
is a decision, not a bug fix.
"""
import json
from pathlib import Path

from codesight_mcp.core.limits import (
    MAX_FILE_SIZE,
    MAX_FILE_COUNT,
    MAX_INDEX_SIZE,
    MAX_DIRECTORY_DEPTH,
)
from codesight_mcp.storage.index_store import INDEX_VERSION
from codesight_mcp.core.freshness import INDEX_AGE_THRESHOLD_DAYS
from codesight_mcp.tools.registry import load_all_specs
from codesight_mcp.parser.languages import LANGUAGE_REGISTRY


def test_max_file_size_is_500kb():
    assert MAX_FILE_SIZE == 500 * 1024  # Changing this requires a spec change.


def test_max_file_count_is_5000():
    assert MAX_FILE_COUNT == 5000  # Changing this requires a spec change.


def test_max_index_size_is_200mb():
    assert MAX_INDEX_SIZE == 200 * 1024 * 1024  # Changing this requires a spec change.


def test_max_directory_depth_is_10():
    assert MAX_DIRECTORY_DEPTH == 10  # Changing this requires a spec change.


def test_index_version_is_2():
    assert INDEX_VERSION == 2  # Changing this requires a spec change.


def test_freshness_threshold_is_7_days():
    assert INDEX_AGE_THRESHOLD_DAYS == 7  # Changing this requires a spec change.


def test_ops_count_matches_contract():
    contract_path = Path(__file__).resolve().parents[2] / "contract" / "operations.json"
    with open(contract_path) as f:
        contract = json.load(f)
    assert len(load_all_specs()) == len(contract["operations"])  # Changing this requires a spec change.


def test_language_count_is_66():
    assert len(LANGUAGE_REGISTRY) == 66  # Changing this requires a spec change.
