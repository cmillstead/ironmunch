"""Export the canonical codesight operation contract from the live registry.
Source of truth for the out-of-repo TS dispatch wrapper (codesight-plugin).
`python scripts/export_contract.py --write` regenerates contract/operations.json.
"""

import argparse
import json
from pathlib import Path

from codesight_mcp.tools.registry import load_all_specs

_CONTRACT_PATH = Path(__file__).resolve().parent.parent / "contract" / "operations.json"

# Prose keys that document a schema for humans but carry no shape/trust
# information. Dropped so the contract stays stable against docstring edits.
_PROSE_KEYS = frozenset({"description", "title"})

# Parameter names that look like they carry a filesystem/repo path, used to
# guard against a newly-added path parameter slipping through unclassified
# (see _classify_path below).
_PATH_ISH_NAMES = frozenset({
    "path", "file_path", "path_prefix", "file",
    "file_pattern", "repo_path", "storage_path", "dir",
})

# Per-(operation, parameter) path classification. Keyed by pair rather than
# bare parameter name because the same name means different things on
# different tools -- e.g. "path" is a real host filesystem path on
# index-folder but a repo-relative filter prefix on analyze-complexity.
# Mirrors the wrapper's three trust loops (host_path / repo_relative_path /
# glob). Verified against the live schemas in src/codesight_mcp/tools/*.py.
_PATH_CLASS_MAP: dict[tuple[str, str], str] = {
    # host_path -- a real path on the machine running the server.
    ("index-folder", "path"): "host_path",
    ("check-licenses", "repo_path"): "host_path",
    ("generate-sbom", "repo_path"): "host_path",
    ("get-changes", "repo_path"): "host_path",
    ("trace-taint", "repo_path"): "host_path",
    ("compare-symbols", "storage_path"): "host_path",
    # host_path -- the index-on-demand working-folder key threaded through the
    # repo-scoped read ops. A missing/stale index for the named repo is built
    # from this folder via the validated index_folder pipeline.
    ("analyze-complexity", "repo_path"): "host_path",
    ("get-call-chain", "repo_path"): "host_path",
    ("get-callees", "repo_path"): "host_path",
    ("get-callers", "repo_path"): "host_path",
    ("get-dead-code", "repo_path"): "host_path",
    ("get-dependencies", "repo_path"): "host_path",
    ("get-diagram", "repo_path"): "host_path",
    ("get-file-outline", "repo_path"): "host_path",
    ("get-file-tree", "repo_path"): "host_path",
    ("get-impact", "repo_path"): "host_path",
    ("get-imports", "repo_path"): "host_path",
    ("get-key-symbols", "repo_path"): "host_path",
    ("get-repo-outline", "repo_path"): "host_path",
    ("get-symbol", "repo_path"): "host_path",
    ("get-symbol-context", "repo_path"): "host_path",
    ("get-symbols", "repo_path"): "host_path",
    ("get-type-hierarchy", "repo_path"): "host_path",
    ("lint-index", "repo_path"): "host_path",
    ("scan-security", "repo_path"): "host_path",
    ("search-references", "repo_path"): "host_path",
    ("search-symbols", "repo_path"): "host_path",
    ("search-text", "repo_path"): "host_path",
    # repo_relative_path -- a path/prefix interpreted inside an indexed repo.
    ("analyze-complexity", "path"): "repo_relative_path",
    ("get-key-symbols", "path"): "repo_relative_path",
    ("get-diagram", "path"): "repo_relative_path",
    ("get-symbol", "file_path"): "repo_relative_path",
    ("get-file-outline", "file_path"): "repo_relative_path",
    ("get-imports", "file"): "repo_relative_path",
    ("get-file-tree", "path_prefix"): "repo_relative_path",
    # glob -- a filename glob pattern, not a path itself.
    ("search-text", "file_pattern"): "glob",
    ("search-symbols", "file_pattern"): "glob",
    ("search-references", "file_pattern"): "glob",
}


def _classify_path(op: str, param_name: str) -> str | None:
    """Classify a parameter's path semantics, or None if it isn't a path.

    Looks up ``(op, param_name)`` in ``_PATH_CLASS_MAP``. If the parameter
    isn't in the map but its name matches ``_PATH_ISH_NAMES`` (a path-looking
    name introduced without a reviewed classification), raises ValueError
    instead of silently emitting null -- a future path parameter must be
    triaged and added to the map, not fall through unclassified.
    """
    classified = _PATH_CLASS_MAP.get((op, param_name))
    if classified is not None:
        return classified
    if param_name in _PATH_ISH_NAMES:
        raise ValueError(
            f"Unclassified path-ish parameter '{param_name}' on operation "
            f"'{op}' -- add it to _PATH_CLASS_MAP in scripts/export_contract.py"
        )
    return None


def _clean_schema(node: object, op: str) -> object:
    """Recursively canonicalize a JSON-Schema node.

    Preserves every structural keyword (type, enum, default, minimum,
    maximum, items, maxItems, minItems, required, properties,
    additionalProperties, pattern, etc.) at every nesting level. Drops only
    human-prose keys (description, title). ``required`` arrays are sorted
    for determinism; ``enum``/``items`` order is left untouched since it's
    stable in source. Each entry under a ``properties`` map gets a
    ``path_class`` key attached (see _classify_path), keyed by its own
    (immediate) property name -- current schemas are flat, so this covers
    every parameter without needing a dotted nested path.
    """
    if isinstance(node, dict):
        cleaned: dict = {}
        for key, value in node.items():
            if key in _PROSE_KEYS:
                continue
            if key == "required" and isinstance(value, list):
                cleaned[key] = sorted(value)
            elif key == "properties" and isinstance(value, dict):
                cleaned[key] = {
                    prop_name: _attach_path_class(
                        _clean_schema(prop_schema, op), op, prop_name,
                    )
                    for prop_name, prop_schema in value.items()
                }
            else:
                cleaned[key] = _clean_schema(value, op)
        return cleaned
    if isinstance(node, list):
        return [_clean_schema(item, op) for item in node]
    return node


def _attach_path_class(prop_schema: object, op: str, prop_name: str) -> object:
    """Attach a ``path_class`` key to a cleaned property schema node."""
    if not isinstance(prop_schema, dict):
        return prop_schema
    return {**prop_schema, "path_class": _classify_path(op, prop_name)}


def build_contract() -> dict:
    """Build the canonical operation contract from the live tool registry."""
    ops = {}
    for name, spec in sorted(load_all_specs().items()):
        op = name.replace("_", "-")
        ops[op] = {
            "operation": op,
            "untrusted": bool(spec.untrusted),
            "destructive": bool(spec.destructive),
            "index_gate": bool(spec.index_gate),
            "required_args": sorted(spec.required_args or []),
            "ci_exit_key": spec.ci_exit_key,
            "params": _clean_schema(spec.input_schema, op),
        }
    return {"version": 1, "operations": ops}


def _render(contract: dict) -> str:
    """Render a contract dict as deterministic, byte-stable JSON text."""
    return json.dumps(contract, indent=2, sort_keys=True) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write", action="store_true",
        help="Write the rendered contract to contract/operations.json instead of stdout.",
    )
    args = parser.parse_args()

    rendered = _render(build_contract())

    if args.write:
        _CONTRACT_PATH.parent.mkdir(exist_ok=True)
        _CONTRACT_PATH.write_text(rendered)
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
