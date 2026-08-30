"""Byte-compare drift test for contract/operations.json.

contract/operations.json is the source of truth for the out-of-repo TS
dispatch wrapper (codesight-plugin). This test fails loudly if the committed
snapshot drifts from what the live registry would export -- run
`python scripts/export_contract.py --write` and commit the result.
"""

from pathlib import Path

from scripts.export_contract import _CONTRACT_PATH, _render, build_contract


def test_contract_snapshot_is_current_bytewise():
    live = _render(build_contract())
    committed = Path(_CONTRACT_PATH).read_text()
    assert committed == live, (
        "contract/operations.json is stale -- run "
        "`python scripts/export_contract.py --write` and commit."
    )


def test_contract_preserves_nested_schema_constraints():
    """A future flatten of the schema export must fail this test loudly."""
    ops = build_contract()["operations"]

    # limit's machine-readable bounds (Task 1) must survive into the export,
    # not just its type.
    for op_name in ("scan-security", "get-dead-code"):
        limit_prop = ops[op_name]["params"]["properties"]["limit"]
        assert limit_prop["minimum"] == 1
        assert limit_prop["maximum"] == 100

    # An array param's items/maxItems constraints must survive.
    repos_prop = ops["search-text"]["params"]["properties"]["repos"]
    assert repos_prop["items"] == {"type": "string"}
    assert repos_prop["maxItems"] == 5


def test_contract_classifies_path_parameters():
    """Per-parameter path_class must distinguish host paths from globs."""
    ops = build_contract()["operations"]

    path_prop = ops["index-folder"]["params"]["properties"]["path"]
    assert path_prop["path_class"] == "host_path"

    pattern_prop = ops["search-text"]["params"]["properties"]["file_pattern"]
    assert pattern_prop["path_class"] == "glob"

    # The index-on-demand working-folder key is a real host path on every
    # repo-scoped read op it was threaded through -- and stays distinct from a
    # co-existing repo-relative path filter on the same op.
    for op_name in ("search-text", "get-callers", "analyze-complexity"):
        ondemand = ops[op_name]["params"]["properties"]["repo_path"]
        assert ondemand["path_class"] == "host_path", op_name
    analyze_path = ops["analyze-complexity"]["params"]["properties"]["path"]
    assert analyze_path["path_class"] == "repo_relative_path"

    # Non-path params (e.g. a plain repo identifier) classify as None.
    repo_prop = ops["get-changes"]["params"]["properties"]["repo"]
    assert repo_prop["path_class"] is None
