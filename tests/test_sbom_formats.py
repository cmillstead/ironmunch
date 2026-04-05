"""Tests for CycloneDX and SPDX SBOM format output."""

import os
import re
import tempfile

from codesight_mcp.tools.generate_sbom import generate_sbom

_UVLOCK_CONTENT = """\
[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "flask"
version = "3.0.0"
"""

_UVLOCK_MISSING_VERSION = """\
[[package]]
name = "requests"

[[package]]
name = "flask"
version = "3.0.0"
"""


def _make_repo_with_uvlock(content: str = _UVLOCK_CONTENT) -> str:
    """Create temp dir with a minimal uv.lock file."""
    tmpdir = tempfile.mkdtemp()
    uvlock = os.path.join(tmpdir, "uv.lock")
    with open(uvlock, "w") as fh:
        fh.write(content)
    return tmpdir


class TestCycloneDXFormat:
    """AC-3: CycloneDX format output."""

    def test_cyclonedx_has_required_fields(self):
        tmpdir = _make_repo_with_uvlock()
        try:
            result = generate_sbom(tmpdir, format="cyclonedx")
            assert result["bomFormat"] == "CycloneDX"
            assert result["specVersion"] == "1.5"
        finally:
            _cleanup(tmpdir)

    def test_cyclonedx_components_count(self):
        tmpdir = _make_repo_with_uvlock()
        try:
            result = generate_sbom(tmpdir, format="cyclonedx")
            assert len(result["components"]) == 2
        finally:
            _cleanup(tmpdir)

    def test_cyclonedx_component_fields(self):
        tmpdir = _make_repo_with_uvlock()
        try:
            result = generate_sbom(tmpdir, format="cyclonedx")
            for component in result["components"]:
                assert component["type"] == "library"
                assert isinstance(component["name"], str)
                assert isinstance(component["version"], str)
                assert isinstance(component["purl"], str)
        finally:
            _cleanup(tmpdir)

    def test_cyclonedx_missing_version(self):
        tmpdir = _make_repo_with_uvlock(_UVLOCK_MISSING_VERSION)
        try:
            result = generate_sbom(tmpdir, format="cyclonedx")
            no_version = [c for c in result["components"] if c["name"] == "requests"]
            assert len(no_version) == 1
            assert no_version[0]["version"] == ""
        finally:
            _cleanup(tmpdir)

    def test_cyclonedx_meta_untrusted(self):
        tmpdir = _make_repo_with_uvlock()
        try:
            result = generate_sbom(tmpdir, format="cyclonedx")
            assert result["_meta"]["trusted"] is False
            assert result["_meta"]["source"] == "lockfile_parse"
        finally:
            _cleanup(tmpdir)

    def test_cyclonedx_no_repo_path(self):
        tmpdir = _make_repo_with_uvlock()
        try:
            result = generate_sbom(tmpdir, format="cyclonedx")
            assert "repo_path" not in result
        finally:
            _cleanup(tmpdir)


class TestSPDXFormat:
    """AC-4: SPDX format output."""

    def test_spdx_has_required_fields(self):
        tmpdir = _make_repo_with_uvlock()
        try:
            result = generate_sbom(tmpdir, format="spdx")
            assert result["spdxVersion"] == "SPDX-2.3"
            assert result["dataLicense"] == "CC0-1.0"
        finally:
            _cleanup(tmpdir)

    def test_spdx_packages_count(self):
        tmpdir = _make_repo_with_uvlock()
        try:
            result = generate_sbom(tmpdir, format="spdx")
            assert len(result["packages"]) == 2
        finally:
            _cleanup(tmpdir)

    def test_spdx_package_fields(self):
        tmpdir = _make_repo_with_uvlock()
        try:
            result = generate_sbom(tmpdir, format="spdx")
            for pkg in result["packages"]:
                assert isinstance(pkg["SPDXID"], str)
                assert isinstance(pkg["name"], str)
                assert isinstance(pkg["versionInfo"], str)
                assert isinstance(pkg["externalRefs"], list)
                purls = [
                    ref for ref in pkg["externalRefs"]
                    if ref.get("referenceType") == "purl"
                ]
                assert len(purls) >= 1
        finally:
            _cleanup(tmpdir)

    def test_spdx_id_sanitized(self):
        """SPDXID should only contain alphanumeric + dash characters."""
        # Create a uv.lock with a package name containing special chars
        content = """\
[[package]]
name = "@scope/name"
version = "1.0.0"
"""
        tmpdir = _make_repo_with_uvlock(content)
        try:
            result = generate_sbom(tmpdir, format="spdx")
            for pkg in result["packages"]:
                spdx_id = pkg["SPDXID"]
                # After the "SPDXRef-Package-" prefix, only alphanumeric + dash
                assert re.match(r"^SPDXRef-Package-[a-zA-Z0-9-]+-\d+$", spdx_id), (
                    f"SPDXID contains invalid characters: {spdx_id}"
                )
        finally:
            _cleanup(tmpdir)

    def test_spdx_namespace_is_url(self):
        tmpdir = _make_repo_with_uvlock()
        try:
            result = generate_sbom(tmpdir, format="spdx")
            assert result["documentNamespace"].startswith("https://")
        finally:
            _cleanup(tmpdir)

    def test_spdx_no_local_paths(self):
        tmpdir = _make_repo_with_uvlock()
        try:
            result = generate_sbom(tmpdir, format="spdx")
            result_str = str(result)
            assert tmpdir not in result_str
        finally:
            _cleanup(tmpdir)

    def test_spdx_meta_untrusted(self):
        tmpdir = _make_repo_with_uvlock()
        try:
            result = generate_sbom(tmpdir, format="spdx")
            assert result["_meta"]["trusted"] is False
        finally:
            _cleanup(tmpdir)

    def test_spdx_missing_version(self):
        tmpdir = _make_repo_with_uvlock(_UVLOCK_MISSING_VERSION)
        try:
            result = generate_sbom(tmpdir, format="spdx")
            no_version = [p for p in result["packages"] if p["name"] == "requests"]
            assert len(no_version) == 1
            assert no_version[0]["versionInfo"] == ""
        finally:
            _cleanup(tmpdir)


class TestFormatBackwardCompat:
    """Backward compatibility tests for format parameter."""

    def test_default_format_unchanged(self):
        tmpdir = _make_repo_with_uvlock()
        try:
            result = generate_sbom(tmpdir)
            assert "dependencies" in result
            assert "summary" in result
        finally:
            _cleanup(tmpdir)

    def test_codesight_format_explicit(self):
        tmpdir = _make_repo_with_uvlock()
        try:
            result = generate_sbom(tmpdir, format="codesight")
            assert "dependencies" in result
            assert "summary" in result
        finally:
            _cleanup(tmpdir)

    def test_invalid_format_returns_error(self):
        tmpdir = _make_repo_with_uvlock()
        try:
            result = generate_sbom(tmpdir, format="xml")
            assert "error" in result
        finally:
            _cleanup(tmpdir)


def _cleanup(tmpdir: str) -> None:
    """Remove temp directory and its contents."""
    uvlock = os.path.join(tmpdir, "uv.lock")
    if os.path.exists(uvlock):
        os.remove(uvlock)
    if os.path.isdir(tmpdir):
        os.rmdir(tmpdir)
