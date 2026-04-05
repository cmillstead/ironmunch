"""Generate a Software Bill of Materials (SBOM) by parsing lockfiles."""

import hashlib
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

# Lockfiles to scan at repo root, in discovery order.
_LOCKFILE_NAMES = [
    "uv.lock",
    "requirements.txt",
    "pyproject.toml",
    "package-lock.json",
    "yarn.lock",
    "Cargo.lock",
    "go.mod",
    "Gemfile.lock",
    "pom.xml",
]

# Maximum file size to read (10 MB).
_MAX_FILE_BYTES = 10 * 1024 * 1024

# Lockfiles we can actually parse.
_PARSERS: dict[str, str] = {
    "uv.lock": "parse_uv_lock",
    "requirements.txt": "parse_requirements_txt",
    "pyproject.toml": "parse_pyproject_toml",
    "package-lock.json": "parse_package_lock_json",
    "Cargo.lock": "parse_cargo_lock",
    "go.mod": "parse_go_mod",
}


# ---------------------------------------------------------------------------
# Parsers — each returns (deps_list, warnings_list)
# ---------------------------------------------------------------------------


def parse_uv_lock(content: str) -> tuple[list[dict], list[dict]]:
    """Parse a uv.lock file (TOML with [[package]] entries).

    Returns (dependencies, warnings).
    """
    deps: list[dict] = []
    warnings: list[dict] = []

    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        warnings.append({"warning": f"TOML parse error: {exc}"})
        return deps, warnings

    for pkg in data.get("package", []):
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name")
        version = pkg.get("version")
        if name:
            deps.append({"name": name, "version": version, "ecosystem": "pypi"})

    return deps, warnings


def parse_requirements_txt(content: str) -> tuple[list[dict], list[dict]]:
    """Parse a requirements.txt file.

    Returns (dependencies, warnings).
    """
    deps: list[dict] = []
    warnings: list[dict] = []

    for line_no, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()

        # Skip blank lines and comments
        if not line or line.startswith("#"):
            continue

        # Skip directives and unsupported entries
        if line.startswith(("-r", "-c", "-e", "--hash")):
            warnings.append({"line": line_no, "warning": f"Skipped: {line}"})
            continue

        if line.startswith("http://") or line.startswith("https://"):
            warnings.append({"line": line_no, "warning": f"Skipped: {line}"})
            continue

        # Parse name==version or name>=version or bare name
        match = re.match(r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)", line)
        if not match:
            warnings.append({"line": line_no, "warning": f"Skipped: {line}"})
            continue

        name = match.group(1)
        version: Optional[str] = None

        version_match = re.search(r"==\s*([^\s;,]+)", line)
        if version_match:
            version = version_match.group(1)

        deps.append({"name": name, "version": version, "ecosystem": "pypi"})

    return deps, warnings


def parse_pyproject_toml(content: str) -> tuple[list[dict], list[dict]]:
    """Parse project.dependencies from a pyproject.toml file.

    Returns (dependencies, warnings).
    """
    deps: list[dict] = []
    warnings: list[dict] = []

    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        warnings.append({"warning": f"TOML parse error: {exc}"})
        return deps, warnings

    dep_strings = data.get("project", {}).get("dependencies", [])

    name_re = re.compile(r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)")
    version_re = re.compile(r"==\s*([^\s;,]+)")

    for dep_str in dep_strings:
        match = name_re.match(dep_str)
        if not match:
            warnings.append({"warning": f"Unparseable dependency: {dep_str}"})
            continue

        name = match.group(1)
        version: Optional[str] = None

        ver_match = version_re.search(dep_str)
        if ver_match:
            version = ver_match.group(1)

        deps.append({"name": name, "version": version, "ecosystem": "pypi"})

    return deps, warnings


def parse_package_lock_json(content: str) -> tuple[list[dict], list[dict]]:
    """Parse a package-lock.json file (v1, v2, and v3).

    Returns (dependencies, warnings).
    """
    deps: list[dict] = []
    warnings: list[dict] = []

    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        warnings.append({"warning": f"JSON parse error: {exc}"})
        return deps, warnings

    # v2/v3: packages dict
    packages = data.get("packages")
    if packages and isinstance(packages, dict):
        for path_key, info in packages.items():
            if not path_key:  # skip root entry
                continue
            if not isinstance(info, dict):
                continue

            # Extract name from path: node_modules/@scope/name or node_modules/name
            parts = path_key.split("node_modules/")
            if not parts or not parts[-1]:
                continue
            name = parts[-1]

            version = info.get("version")
            deps.append({"name": name, "version": version, "ecosystem": "npm"})
        return deps, warnings

    # v1: dependencies dict (recursive — nested deps have their own dependencies)
    dependencies = data.get("dependencies")
    if dependencies and isinstance(dependencies, dict):
        _collect_npm_v1_deps(dependencies, deps)

    return deps, warnings


def _collect_npm_v1_deps(dependencies: dict, deps: list[dict]) -> None:
    """Recursively collect deps from npm v1 package-lock dependencies dict."""
    for name, info in dependencies.items():
        if not isinstance(info, dict):
            continue
        version = info.get("version")
        deps.append({"name": name, "version": version, "ecosystem": "npm"})
        # Recurse into nested dependencies
        nested = info.get("dependencies")
        if nested and isinstance(nested, dict):
            _collect_npm_v1_deps(nested, deps)


def parse_cargo_lock(content: str) -> tuple[list[dict], list[dict]]:
    """Parse a Cargo.lock file.

    Returns (dependencies, warnings).
    """
    deps: list[dict] = []
    warnings: list[dict] = []

    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        warnings.append({"warning": f"TOML parse error: {exc}"})
        return deps, warnings

    for pkg in data.get("package", []):
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name")
        version = pkg.get("version")
        if name:
            deps.append({"name": name, "version": version, "ecosystem": "cargo"})

    return deps, warnings


def parse_go_mod(content: str) -> tuple[list[dict], list[dict]]:
    """Parse a go.mod file.

    Returns (dependencies, warnings).
    """
    deps: list[dict] = []
    warnings: list[dict] = []

    # Full Go version: v1.2.3, v1.2.3+incompatible, v0.0.0-20240101-abcdef123456
    require_re = re.compile(r"^\s*(\S+)\s+(v\S+)")

    in_require_block = False
    for line in content.splitlines():
        stripped = line.strip()

        if stripped.startswith("require ("):
            in_require_block = True
            continue

        if in_require_block and stripped == ")":
            in_require_block = False
            continue

        if in_require_block:
            match = require_re.match(stripped)
            if match:
                deps.append({
                    "name": match.group(1),
                    "version": match.group(2),
                    "ecosystem": "golang",
                })
            continue

        # Single-line require
        if stripped.startswith("require "):
            remainder = stripped[len("require "):]
            match = require_re.match(remainder)
            if match:
                deps.append({
                    "name": match.group(1),
                    "version": match.group(2),
                    "ecosystem": "golang",
                })

    return deps, warnings


# ---------------------------------------------------------------------------
# PURL generation
# ---------------------------------------------------------------------------

_ECOSYSTEM_MAP = {
    "pypi": "pypi",
    "npm": "npm",
    "cargo": "cargo",
    "golang": "golang",
    "gem": "gem",
}


def _make_purl(dep: dict) -> str:
    """Build a Package URL (purl) from a dependency dict."""
    purl_type = _ECOSYSTEM_MAP.get(dep["ecosystem"], dep["ecosystem"])
    name = dep["name"]
    if dep["ecosystem"] == "npm" and name.startswith("@"):
        name = "%40" + name[1:]  # Encode @ for scoped packages
    purl = f"pkg:{purl_type}/{name}"
    if dep.get("version"):
        purl += f"@{dep['version']}"
    return purl


# ---------------------------------------------------------------------------
# Main handler
# ---------------------------------------------------------------------------


def generate_sbom(
    repo_path: str,
    allowed_roots: Optional[list[str]] = None,
    format: str = "codesight",
) -> dict:
    """Generate an SBOM by parsing lockfiles at the repo root.

    Args:
        repo_path: Filesystem path to the repository root.
        allowed_roots: Optional list of allowed root directories.
        format: Output format — "codesight" (default), "cyclonedx", or "spdx".

    Returns:
        Dict with dependencies, lockfile info, and _meta envelope.
    """
    valid_formats = {"codesight", "cyclonedx", "spdx"}
    if format not in valid_formats:
        return {"error": f"Invalid format: {format!r}. Must be one of: codesight, cyclonedx, spdx"}

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

    lockfiles_found: list[str] = []
    lockfiles_parsed: list[str] = []
    lockfiles_skipped: list[dict] = []
    deps_raw: list[dict] = []
    all_warnings: list[dict] = []

    # Track parsed ecosystems to avoid double-counting (e.g., uv.lock + pyproject.toml)
    parsed_ecosystems: set[str] = set()

    for filename in _LOCKFILE_NAMES:
        filepath = os.path.join(str(resolved_path), filename)

        if not os.path.isfile(filepath):
            continue

        lockfiles_found.append(filename)

        # Skip pyproject.toml if any Python lockfile already parsed (avoids double-counting)
        if filename == "pyproject.toml" and "pypi" in parsed_ecosystems:
            lockfiles_skipped.append({
                "file": wrap_untrusted_content(filename),
                "reason": "Skipped: Python lockfile already parsed",
            })
            continue

        # Symlink protection: ensure real path stays within repo root
        real_filepath = os.path.realpath(filepath)
        real_repo = os.path.realpath(str(resolved_path))
        if not real_filepath.startswith(real_repo + os.sep) and real_filepath != real_repo:
            lockfiles_skipped.append({
                "file": wrap_untrusted_content(filename),
                "reason": "Symlink points outside repository root",
            })
            continue

        # Check for parser support
        parser_name = _PARSERS.get(filename)
        if parser_name is None:
            lockfiles_skipped.append({
                "file": wrap_untrusted_content(filename),
                "reason": f"Parsing not supported for {filename}",
            })
            continue

        # Size check
        try:
            file_size = os.path.getsize(filepath)
        except OSError:
            lockfiles_skipped.append({
                "file": wrap_untrusted_content(filename),
                "reason": "Unable to read file size",
            })
            continue

        if file_size > _MAX_FILE_BYTES:
            lockfiles_skipped.append({
                "file": wrap_untrusted_content(filename),
                "reason": f"File exceeds {_MAX_FILE_BYTES // (1024 * 1024)}MB limit ({file_size} bytes)",
            })
            continue

        # Read and parse
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError as exc:
            lockfiles_skipped.append({
                "file": wrap_untrusted_content(filename),
                "reason": f"Read error: {exc}",
            })
            continue

        parser_fn = globals()[parser_name]
        deps, parse_warnings = parser_fn(content)

        lockfiles_parsed.append(filename)

        # Track which ecosystems have been parsed
        for dep in deps:
            parsed_ecosystems.add(dep.get("ecosystem", ""))

        # Attach source and purl to each dep as plain strings (raw)
        for dep in deps:
            dep["purl"] = _make_purl(dep)
            dep["source"] = filename
            deps_raw.append(dep)

        # Collect warnings (wrap strings for all formats)
        for warn in parse_warnings:
            wrapped_warn = {}
            for key, val in warn.items():
                if isinstance(val, str):
                    wrapped_warn[key] = wrap_untrusted_content(val)
                else:
                    wrapped_warn[key] = val
            all_warnings.append(wrapped_warn)

    ms = elapsed_ms(start)

    # Branch on output format
    if format == "cyclonedx":
        return _format_cyclonedx(deps_raw, lockfiles_parsed, ms)
    if format == "spdx":
        return _format_spdx(deps_raw, lockfiles_parsed, ms)

    # Default: "codesight" format — wrap deps with untrusted markers
    all_deps: list[dict] = []
    for dep in deps_raw:
        wrapped = dict(dep)
        wrapped["name"] = wrap_untrusted_content(dep["name"])
        if dep["version"] is not None:
            wrapped["version"] = wrap_untrusted_content(dep["version"])
        wrapped["purl"] = wrap_untrusted_content(dep["purl"])
        wrapped["source"] = wrap_untrusted_content(dep["source"])
        all_deps.append(wrapped)

    # Build summary
    by_ecosystem: dict[str, int] = {}
    for dep in all_deps:
        eco = dep["ecosystem"]
        by_ecosystem[eco] = by_ecosystem.get(eco, 0) + 1

    return {
        "repo_path": str(resolved_path),
        "lockfiles_found": [wrap_untrusted_content(f) for f in lockfiles_found],
        "lockfiles_parsed": [wrap_untrusted_content(f) for f in lockfiles_parsed],
        "lockfiles_skipped": lockfiles_skipped,
        "parse_warnings": all_warnings,
        "dependencies": all_deps,
        "summary": {"total": len(all_deps), "by_ecosystem": by_ecosystem},
        "warnings": [
            "Only top-level lockfiles scanned. Nested manifests not discovered.",
        ],
        "_meta": {
            **make_meta(source="lockfile_parse", trusted=False),
            "timing_ms": ms,
        },
    }


# ---------------------------------------------------------------------------
# Standards format helpers
# ---------------------------------------------------------------------------


def _format_cyclonedx(
    deps_raw: list[dict],
    lockfiles_parsed: list[str],
    timing_ms: float,
) -> dict:
    """Format raw deps as CycloneDX 1.5 JSON."""
    from datetime import datetime, timezone

    components = []
    for dep in deps_raw:
        components.append({
            "type": "library",
            "name": dep["name"],
            "version": dep.get("version") or "",
            "purl": dep["purl"],
        })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"name": "codesight-mcp"}],
        },
        "components": components,
        "_meta": {
            "source": "lockfile_parse",
            "trusted": False,
            "timing_ms": timing_ms,
        },
    }


def _sanitize_spdx_id(name: str) -> str:
    """Sanitize name for use in SPDX IDs (alphanumeric + dash only)."""
    return re.sub(r"[^a-zA-Z0-9-]", "-", name)


def _format_spdx(
    deps_raw: list[dict],
    lockfiles_parsed: list[str],
    timing_ms: float,
) -> dict:
    """Format raw deps as SPDX 2.3 JSON."""
    from datetime import datetime, timezone

    namespace_input = "|".join(sorted(lockfiles_parsed))
    namespace_hash = hashlib.sha256(namespace_input.encode()).hexdigest()[:16]

    packages = []
    for idx, dep in enumerate(deps_raw):
        sanitized = _sanitize_spdx_id(dep["name"])
        packages.append({
            "SPDXID": f"SPDXRef-Package-{sanitized}-{idx}",
            "name": dep["name"],
            "versionInfo": dep.get("version") or "",
            "downloadLocation": "NOASSERTION",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": dep["purl"],
            }],
        })
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "codesight-sbom",
        "documentNamespace": f"https://codesight-mcp/sbom/{namespace_hash}",
        "creationInfo": {
            "created": datetime.now(timezone.utc).isoformat(),
            "creators": ["Tool: codesight-mcp"],
        },
        "packages": packages,
        "_meta": {
            "source": "lockfile_parse",
            "trusted": False,
            "timing_ms": timing_ms,
        },
    }


# ---------------------------------------------------------------------------
# Handler wrapper + allowed-roots wiring (same pattern as get_changes.py)
# ---------------------------------------------------------------------------


def _handle_generate_sbom(args: dict, storage_path, *, _allowed_roots_fn=None):
    """Handler that resolves ALLOWED_ROOTS at call time."""
    if _handle_generate_sbom._allowed_roots_fn is not None:
        allowed = _handle_generate_sbom._allowed_roots_fn()
    else:
        allowed = None
    return generate_sbom(
        repo_path=args["repo_path"],
        allowed_roots=allowed,
        format=args.get("format", "codesight"),
    )


_handle_generate_sbom._allowed_roots_fn = None


def set_allowed_roots_fn(fn):
    """Set the function that returns ALLOWED_ROOTS. Called by server.py."""
    _handle_generate_sbom._allowed_roots_fn = fn


_spec = register(ToolSpec(
    name="generate_sbom",
    description=(
        "Generate a Software Bill of Materials (SBOM) by parsing lockfiles "
        "in a repository. Discovers and parses requirements.txt, pyproject.toml, "
        "package-lock.json, Cargo.lock, and go.mod at the repo root. Returns "
        "dependency names, versions, ecosystems, and Package URLs (purls)."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "repo_path": {
                "type": "string",
                "description": "Filesystem path to the repository root",
            },
            "format": {
                "type": "string",
                "enum": ["codesight", "cyclonedx", "spdx"],
                "default": "codesight",
                "description": "Output format: codesight (default), cyclonedx, or spdx",
            },
        },
        "required": ["repo_path"],
    },
    handler=lambda args, storage_path: _handle_generate_sbom(args, storage_path),
    required_args=["repo_path"],
    untrusted=True,
    annotations=ToolAnnotations(
        title="Generate SBOM",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
))
