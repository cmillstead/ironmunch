"""Check project and dependency licenses from manifest files."""

import json
import logging
import os
import re
import tomllib
from pathlib import Path
from typing import Optional

from mcp.types import ToolAnnotations

from ..core.boundaries import make_meta, wrap_untrusted_content
from ..core.validation import is_within
from ._common import timed, elapsed_ms
from .registry import ToolSpec, register

logger = logging.getLogger(__name__)

# Maximum file size to read (10 MB).
_MAX_FILE_BYTES = 10 * 1024 * 1024

# Manifest files to scan at repo root, in discovery order.
_MANIFEST_NAMES = [
    "pyproject.toml",
    "package.json",
    "Cargo.toml",
    "package-lock.json",
]

# ---------------------------------------------------------------------------
# License normalization
# ---------------------------------------------------------------------------

_NORMALIZE_MAP: dict[str, str] = {
    "MIT License": "MIT",
    "Apache License 2.0": "Apache-2.0",
    "Apache License, Version 2.0": "Apache-2.0",
    "BSD License": "BSD-3-Clause",
    "ISC License": "ISC",
    "GNU General Public License v3.0": "GPL-3.0",
    "Mozilla Public License 2.0": "MPL-2.0",
}

# ---------------------------------------------------------------------------
# License classification sets
# ---------------------------------------------------------------------------

_PERMISSIVE: frozenset[str] = frozenset({
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC",
    "0BSD", "Unlicense", "CC0-1.0", "Zlib", "BSL-1.0",
})

_COPYLEFT: frozenset[str] = frozenset({
    "GPL-2.0", "GPL-3.0", "LGPL-2.1", "LGPL-3.0", "AGPL-3.0", "MPL-2.0",
    "EUPL-1.2", "GPL-2.0-only", "GPL-3.0-only", "GPL-2.0-or-later",
    "GPL-3.0-or-later", "AGPL-3.0-only", "AGPL-3.0-or-later",
})

# Regex to split SPDX compound expressions.
_SPDX_SPLIT_RE = re.compile(r"\s+(?:OR|AND|WITH)\s+")


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def normalize_license(raw: str) -> str:
    """Normalize common license name variations to SPDX identifiers."""
    return _NORMALIZE_MAP.get(raw, raw)


def classify_license(license_str: str) -> str:
    """Classify a license string as 'permissive', 'copyleft', or 'unknown'.

    For SPDX compound expressions with OR (e.g. ``GPL-3.0 OR MIT``), the
    result is 'permissive' if ANY branch is permissive — because consumers
    can choose the permissive branch.  For AND expressions, all branches
    must be permissive for the result to be permissive.
    """
    normalized = normalize_license(license_str)

    # Split compound expressions.
    parts = _SPDX_SPLIT_RE.split(normalized)
    parts = [p.strip() for p in parts if p.strip()]

    if not parts:
        return "unknown"

    # Check if this is an OR expression (dual-license — consumer chooses)
    is_or = " OR " in normalized.upper()

    classifications = []
    for part in parts:
        norm_part = normalize_license(part)
        if norm_part in _PERMISSIVE:
            classifications.append("permissive")
        elif norm_part in _COPYLEFT:
            classifications.append("copyleft")
        else:
            classifications.append("unknown")

    if is_or:
        # OR: permissive if ANY branch is permissive
        if "permissive" in classifications:
            return "permissive"
        if "copyleft" in classifications:
            return "copyleft"
        return "unknown"
    else:
        # AND/WITH: copyleft if ANY branch is copyleft
        if "copyleft" in classifications:
            return "copyleft"
        if "permissive" in classifications:
            return "permissive"
        return "unknown"


# ---------------------------------------------------------------------------
# Extraction functions
# ---------------------------------------------------------------------------


def extract_license_pyproject(content: str) -> dict | None:
    """Extract project license from pyproject.toml content.

    Returns dict with ``license`` and ``source`` keys, or ``None``.
    """
    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError:
        return None

    license_field = data.get("project", {}).get("license")
    if license_field is None:
        return None

    if isinstance(license_field, str):
        return {"license": license_field, "source": "pyproject.toml"}

    if isinstance(license_field, dict):
        if "text" in license_field:
            return {"license": license_field["text"], "source": "pyproject.toml"}
        if "file" in license_field:
            return {"license": f"See {license_field['file']}", "source": "pyproject.toml"}

    return None


def extract_license_package_json(content: str) -> dict | None:
    """Extract project license from package.json content.

    Returns dict with ``license`` and ``source`` keys, or ``None``.
    """
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return None

    # Single string license field.
    license_field = data.get("license")
    if isinstance(license_field, str):
        return {"license": license_field, "source": "package.json"}

    # Legacy licenses array: [{type: "MIT", url: "..."}]
    licenses_array = data.get("licenses")
    if isinstance(licenses_array, list) and licenses_array:
        first = licenses_array[0]
        if isinstance(first, dict) and "type" in first:
            return {"license": first["type"], "source": "package.json"}

    return None


def extract_license_cargo_toml(content: str) -> dict | None:
    """Extract project license from Cargo.toml content.

    Returns dict with ``license`` and ``source`` keys, or ``None``.
    """
    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError:
        return None

    license_field = data.get("package", {}).get("license")
    if isinstance(license_field, str):
        return {"license": license_field, "source": "Cargo.toml"}

    return None


def extract_dep_licenses_package_lock(content: str) -> list[dict]:
    """Extract per-dependency license info from package-lock.json.

    Handles v2/v3 (``packages`` dict) and v1 (``dependencies`` dict).

    Returns list of dicts with ``name``, ``version``, ``license``, ``source``.
    """
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []

    deps: list[dict] = []

    # v2/v3: packages dict
    packages = data.get("packages")
    if packages and isinstance(packages, dict):
        for path_key, info in packages.items():
            if not path_key:  # skip root entry
                continue
            if not isinstance(info, dict):
                continue

            license_val = info.get("license")
            if not isinstance(license_val, str):
                continue

            # Extract name from path: node_modules/@scope/name or node_modules/name
            parts = path_key.split("node_modules/")
            if not parts or not parts[-1]:
                continue
            name = parts[-1]

            version = info.get("version")
            deps.append({
                "name": name,
                "version": version,
                "license": license_val,
                "source": "package-lock.json",
            })
        return deps

    # v1: dependencies dict (recursive — nested deps have their own dependencies)
    dependencies = data.get("dependencies")
    if dependencies and isinstance(dependencies, dict):
        _collect_v1_licenses(dependencies, deps)

    return deps


def _collect_v1_licenses(dependencies: dict, deps: list[dict]) -> None:
    """Recursively collect license info from npm v1 dependencies dict."""
    for name, info in dependencies.items():
        if not isinstance(info, dict):
            continue
        license_val = info.get("license")
        if isinstance(license_val, str):
            version = info.get("version")
            deps.append({
                "name": name,
                "version": version,
                "license": license_val,
                "source": "package-lock.json",
            })
        # Recurse into nested dependencies
        nested = info.get("dependencies")
        if nested and isinstance(nested, dict):
            _collect_v1_licenses(nested, deps)


# ---------------------------------------------------------------------------
# Main handler
# ---------------------------------------------------------------------------

# Extraction dispatch: filename -> (extractor_fn, is_dep_scanner)
_EXTRACTORS: dict[str, tuple[str, bool]] = {
    "pyproject.toml": ("extract_license_pyproject", False),
    "package.json": ("extract_license_package_json", False),
    "Cargo.toml": ("extract_license_cargo_toml", False),
    "package-lock.json": ("extract_dep_licenses_package_lock", True),
}


def _read_manifest(filepath: str, resolved_path: Path) -> tuple[str | None, str | None]:
    """Read a manifest file with symlink + size safety checks.

    Returns (content, skip_reason).  When skip_reason is not None the file
    should be skipped and the reason recorded as a warning.
    """
    # Symlink protection: ensure real path stays within repo root
    real_filepath = os.path.realpath(filepath)
    real_repo = os.path.realpath(str(resolved_path))
    if not real_filepath.startswith(real_repo + os.sep) and real_filepath != real_repo:
        return None, "Symlink points outside repository root"

    # Size check
    try:
        file_size = os.path.getsize(filepath)
    except OSError:
        return None, "Unable to read file size"

    if file_size > _MAX_FILE_BYTES:
        return None, f"File exceeds {_MAX_FILE_BYTES // (1024 * 1024)}MB limit ({file_size} bytes)"

    # Read
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(), None
    except OSError as exc:
        return None, f"Read error: {exc}"


def check_licenses(
    repo_path: str,
    allowed_roots: Optional[list[str]] = None,
) -> dict:
    """Check project and dependency licenses from manifest files.

    Args:
        repo_path: Filesystem path to the repository root.
        allowed_roots: Optional list of allowed root directories.

    Returns:
        Dict with project license, dependency licenses, summary, and _meta.
    """
    start = timed()

    # Validate repo_path against ALLOWED_ROOTS
    if not repo_path:
        return {"error": "repo_path is required"}

    resolved_path = Path(repo_path).expanduser().resolve()
    if allowed_roots:
        allowed = [Path(r).expanduser().resolve() for r in allowed_roots if r.strip()]
        if not any(is_within(a, resolved_path) or resolved_path == a for a in allowed):
            return {"error": "repo_path is outside allowed roots"}

    if not resolved_path.is_dir():
        return {"error": "repo_path is not a directory"}

    project_license: dict | None = None
    dependency_licenses: list[dict] = []
    parse_warnings: list[str] = []

    for filename in _MANIFEST_NAMES:
        filepath = os.path.join(str(resolved_path), filename)

        if not os.path.isfile(filepath):
            continue

        content, skip_reason = _read_manifest(filepath, resolved_path)
        if skip_reason is not None:
            parse_warnings.append(f"{filename}: {skip_reason}")
            continue

        extractor_name, is_dep_scanner = _EXTRACTORS.get(filename, (None, False))
        if extractor_name is None:
            continue

        if is_dep_scanner:
            # Dependency license scanner (package-lock.json)
            raw_deps = extract_dep_licenses_package_lock(content)
            for dep in raw_deps:
                normalized = normalize_license(dep["license"])
                classification = classify_license(normalized)

                # Check for compound expression warning
                if _SPDX_SPLIT_RE.search(normalized):
                    parse_warnings.append(
                        f"Compound SPDX expression for {dep['name']}: {normalized}"
                    )

                dependency_licenses.append({
                    "name": wrap_untrusted_content(dep["name"]),
                    "version": wrap_untrusted_content(dep["version"]) if dep.get("version") else None,
                    "license": wrap_untrusted_content(normalized),
                    "classification": classification,
                    "source": wrap_untrusted_content(dep["source"]),
                })
        else:
            # Project license extractor
            extractor_fn = globals()[extractor_name]
            result = extractor_fn(content)
            if result is not None and project_license is None:
                normalized = normalize_license(result["license"])
                classification = classify_license(normalized)

                # Check for compound expression warning
                if _SPDX_SPLIT_RE.search(normalized):
                    parse_warnings.append(
                        f"Compound SPDX expression in {result['source']}: {normalized}"
                    )

                project_license = {
                    "license": wrap_untrusted_content(normalized),
                    "source": wrap_untrusted_content(result["source"]),
                    "classification": classification,
                }

    # Build summary
    permissive_count = sum(1 for d in dependency_licenses if d["classification"] == "permissive")
    copyleft_count = sum(1 for d in dependency_licenses if d["classification"] == "copyleft")
    unknown_count = sum(1 for d in dependency_licenses if d["classification"] == "unknown")
    copyleft_packages = [
        d["name"] for d in dependency_licenses if d["classification"] == "copyleft"
    ]

    # Build compliance concerns
    compliance_concerns: list[dict] = []
    for dep in dependency_licenses:
        if dep["classification"] == "copyleft":
            compliance_concerns.append({
                "package": dep["name"],
                "license": dep["license"],
                "concern": "Copyleft license may require source disclosure",
            })

    ms = elapsed_ms(start)

    return {
        "repo_path": str(resolved_path),
        "project_license": project_license,
        "dependency_licenses": dependency_licenses,
        "summary": {
            "total": len(dependency_licenses),
            "permissive": permissive_count,
            "copyleft": copyleft_count,
            "unknown": unknown_count,
            "copyleft_packages": copyleft_packages,
        },
        "compliance_concerns": compliance_concerns,
        "parse_warnings": [wrap_untrusted_content(w) for w in parse_warnings],
        "warnings": [
            "Only top-level manifests scanned. Nested manifests not discovered.",
        ],
        "_meta": {
            **make_meta(source="manifest_parse", trusted=False),
            "timing_ms": ms,
        },
    }


# ---------------------------------------------------------------------------
# Handler wrapper + allowed-roots wiring (same pattern as generate_sbom.py)
# ---------------------------------------------------------------------------


def _handle_check_licenses(args: dict, storage_path, *, _allowed_roots_fn=None):
    """Handler that resolves ALLOWED_ROOTS at call time."""
    if _handle_check_licenses._allowed_roots_fn is not None:
        allowed = _handle_check_licenses._allowed_roots_fn()
    else:
        allowed = None
    return check_licenses(
        repo_path=args["repo_path"],
        allowed_roots=allowed,
    )


_handle_check_licenses._allowed_roots_fn = None


def set_allowed_roots_fn(fn):
    """Set the function that returns ALLOWED_ROOTS. Called by server.py."""
    _handle_check_licenses._allowed_roots_fn = fn


_spec = register(ToolSpec(
    name="check_licenses",
    description=(
        "Check project and dependency licenses by parsing manifest files "
        "in a repository. Discovers pyproject.toml, package.json, Cargo.toml, "
        "and package-lock.json at the repo root. Returns project license, "
        "per-dependency licenses, classification (permissive/copyleft/unknown), "
        "and compliance concerns."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "repo_path": {
                "type": "string",
                "description": "Filesystem path to the repository root",
            },
        },
        "required": ["repo_path"],
    },
    handler=lambda args, storage_path: _handle_check_licenses(args, storage_path),
    required_args=["repo_path"],
    untrusted=True,
    annotations=ToolAnnotations(
        title="Check Licenses",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
))
