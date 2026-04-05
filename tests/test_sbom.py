"""Tests for generate_sbom and check_licenses tools.

Tier 1: Unit tests for parser/classification functions with string inputs.
Tier 2: End-to-end integration tests with real tmp_path directories.
"""

import json

import pytest

from codesight_mcp.tools.generate_sbom import (
    parse_requirements_txt,
    parse_pyproject_toml,
    parse_package_lock_json,
    parse_cargo_lock,
    parse_go_mod,
    _make_purl,
    generate_sbom,
)
from codesight_mcp.tools.check_licenses import (
    normalize_license,
    classify_license,
    extract_license_pyproject,
    extract_license_package_json,
    extract_license_cargo_toml,
    extract_dep_licenses_package_lock,
    check_licenses,
)
from codesight_mcp.tools.registry import get_all_specs


# ===========================================================================
# Tier 1: Unit tests for generate_sbom parsers
# ===========================================================================


class TestParseRequirementsTxt:
    """parse_requirements_txt: pinned, unpinned, skipped lines."""

    def test_parse_requirements_pinned(self):
        content = "flask==3.0.0\nrequests==2.31.0"
        deps, warnings = parse_requirements_txt(content)
        assert len(deps) == 2
        assert deps[0]["name"] == "flask"
        assert deps[0]["version"] == "3.0.0"
        assert deps[0]["ecosystem"] == "pypi"
        assert deps[1]["name"] == "requests"
        assert deps[1]["version"] == "2.31.0"

    def test_parse_requirements_unpinned(self):
        content = "requests\nflask>=3.0"
        deps, warnings = parse_requirements_txt(content)
        assert len(deps) == 2
        assert deps[0]["version"] is None
        assert deps[1]["version"] is None

    def test_parse_requirements_skips(self):
        content = (
            "-r base.txt\n"
            "-e git+https://github.com/foo/bar.git\n"
            "--hash=sha256:abc\n"
            "http://example.com/pkg.tar.gz\n"
            "# this is a comment\n"
            "valid-pkg==1.0\n"
        )
        deps, warnings = parse_requirements_txt(content)
        assert len(deps) == 1
        assert deps[0]["name"] == "valid-pkg"
        # Non-trivial skips emit warnings (not comments or blanks)
        skipped_texts = [w["warning"] for w in warnings]
        assert any("-r base.txt" in text for text in skipped_texts)
        assert any("-e git+" in text for text in skipped_texts)
        assert any("--hash" in text for text in skipped_texts)
        assert any("http://" in text for text in skipped_texts)

    def test_parse_requirements_empty(self):
        deps, warnings = parse_requirements_txt("")
        assert len(deps) == 0
        assert len(warnings) == 0


class TestParsePyprojectToml:
    """parse_pyproject_toml: dependency extraction from [project]."""

    def test_parse_pyproject_deps(self):
        content = '[project]\ndependencies = ["flask>=3.0", "requests==2.31.0"]'
        deps, warnings = parse_pyproject_toml(content)
        assert len(deps) == 2
        flask_dep = next(d for d in deps if d["name"] == "flask")
        requests_dep = next(d for d in deps if d["name"] == "requests")
        assert flask_dep["version"] is None  # >=3.0 is not pinned ==
        assert requests_dep["version"] == "2.31.0"


class TestParsePackageLockJson:
    """parse_package_lock_json: v1, v2/v3 formats."""

    def test_parse_package_lock_v2(self):
        data = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root", "version": "1.0.0"},
                "node_modules/express": {"version": "4.18.2"},
                "node_modules/@scope/pkg": {"version": "1.0.0"},
            },
        }
        deps, warnings = parse_package_lock_json(json.dumps(data))
        assert len(deps) == 2
        names = {d["name"] for d in deps}
        assert "express" in names
        assert "@scope/pkg" in names
        for dep in deps:
            assert dep["ecosystem"] == "npm"

    def test_parse_package_lock_v1(self):
        data = {
            "lockfileVersion": 1,
            "dependencies": {
                "lodash": {"version": "4.17.21"},
                "chalk": {"version": "5.3.0"},
            },
        }
        deps, warnings = parse_package_lock_json(json.dumps(data))
        assert len(deps) == 2
        names = {d["name"] for d in deps}
        assert "lodash" in names
        assert "chalk" in names

    def test_parse_malformed_json(self):
        deps, warnings = parse_package_lock_json("{not valid json")
        assert len(deps) == 0
        assert len(warnings) == 1
        assert "JSON parse error" in warnings[0]["warning"]


class TestParseCargoLock:
    """parse_cargo_lock: TOML [[package]] extraction."""

    def test_parse_cargo_lock(self):
        content = '[[package]]\nname = "serde"\nversion = "1.0.0"'
        deps, warnings = parse_cargo_lock(content)
        assert len(deps) == 1
        assert deps[0]["name"] == "serde"
        assert deps[0]["version"] == "1.0.0"
        assert deps[0]["ecosystem"] == "cargo"


class TestParseGoMod:
    """parse_go_mod: require block with module paths."""

    def test_parse_go_mod(self):
        content = (
            "module example.com/mymod\n\n"
            "go 1.21\n\n"
            "require (\n"
            "\tgithub.com/gin-gonic/gin v1.9.1\n"
            "\tgolang.org/x/text v0.14.0\n"
            ")\n"
        )
        deps, warnings = parse_go_mod(content)
        assert len(deps) == 2
        names = {d["name"] for d in deps}
        assert "github.com/gin-gonic/gin" in names
        assert "golang.org/x/text" in names
        for dep in deps:
            assert dep["ecosystem"] == "golang"
            assert dep["version"].startswith("v")


class TestMakePurl:
    """_make_purl: Package URL construction."""

    def test_purl_with_version(self):
        dep = {"name": "flask", "version": "3.0.0", "ecosystem": "pypi"}
        assert _make_purl(dep) == "pkg:pypi/flask@3.0.0"

    def test_purl_without_version(self):
        dep = {"name": "requests", "version": None, "ecosystem": "pypi"}
        result = _make_purl(dep)
        assert result == "pkg:pypi/requests"
        assert "@" not in result

    def test_purl_scoped_npm(self):
        dep = {"name": "@scope/pkg", "version": "1.0.0", "ecosystem": "npm"}
        assert _make_purl(dep) == "pkg:npm/%40scope/pkg@1.0.0"


# ===========================================================================
# Tier 1: Unit tests for check_licenses functions
# ===========================================================================


class TestNormalizeLicense:
    """normalize_license: common name -> SPDX identifier."""

    def test_normalize_mit_license(self):
        assert normalize_license("MIT License") == "MIT"

    def test_normalize_apache(self):
        assert normalize_license("Apache License 2.0") == "Apache-2.0"

    def test_normalize_already_spdx(self):
        assert normalize_license("MIT") == "MIT"


class TestClassifyLicense:
    """classify_license: permissive, copyleft, unknown."""

    @pytest.mark.parametrize("license_id", ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"])
    def test_classify_permissive(self, license_id):
        assert classify_license(license_id) == "permissive"

    @pytest.mark.parametrize("license_id", ["GPL-3.0", "AGPL-3.0", "LGPL-3.0"])
    def test_classify_copyleft(self, license_id):
        assert classify_license(license_id) == "copyleft"

    def test_classify_unknown(self):
        assert classify_license("CustomLicense") == "unknown"

    def test_classify_spdx_compound(self):
        result = classify_license("MIT OR Apache-2.0")
        assert result == "permissive"


class TestExtractLicensePyproject:
    """extract_license_pyproject: string, table, and missing cases."""

    def test_extract_pyproject_string(self):
        content = '[project]\nlicense = "MIT"'
        result = extract_license_pyproject(content)
        assert result is not None
        assert result["license"] == "MIT"
        assert result["source"] == "pyproject.toml"

    def test_extract_pyproject_table(self):
        content = "[project.license]\ntext = \"MIT\""
        result = extract_license_pyproject(content)
        assert result is not None
        assert result["license"] == "MIT"

    def test_extract_pyproject_none(self):
        content = "[project]\nname = \"mypkg\""
        result = extract_license_pyproject(content)
        assert result is None


class TestExtractLicensePackageJson:
    """extract_license_package_json: string and legacy array forms."""

    def test_extract_package_json(self):
        content = json.dumps({"license": "Apache-2.0"})
        result = extract_license_package_json(content)
        assert result is not None
        assert result["license"] == "Apache-2.0"
        assert result["source"] == "package.json"

    def test_extract_package_json_array(self):
        content = json.dumps({"licenses": [{"type": "MIT", "url": "https://..."}]})
        result = extract_license_package_json(content)
        assert result is not None
        assert result["license"] == "MIT"


class TestExtractLicenseCargoToml:
    """extract_license_cargo_toml: [package] license field."""

    def test_extract_cargo_toml(self):
        content = '[package]\nlicense = "MIT OR Apache-2.0"'
        result = extract_license_cargo_toml(content)
        assert result is not None
        assert result["license"] == "MIT OR Apache-2.0"
        assert result["source"] == "Cargo.toml"


class TestDepLicensesPackageLock:
    """extract_dep_licenses_package_lock: per-package license extraction."""

    def test_dep_licenses_package_lock(self):
        data = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root", "version": "1.0.0"},
                "node_modules/express": {
                    "version": "4.18.2",
                    "license": "MIT",
                },
                "node_modules/left-pad": {
                    "version": "1.3.0",
                    "license": "WTFPL",
                },
            },
        }
        result = extract_dep_licenses_package_lock(json.dumps(data))
        assert len(result) == 2
        licenses = {d["name"]: d["license"] for d in result}
        assert licenses["express"] == "MIT"
        assert licenses["left-pad"] == "WTFPL"

    def test_copyleft_flagged(self):
        """Verify copyleft packages appear in check_licenses summary."""
        data = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root", "version": "1.0.0"},
                "node_modules/gpl-pkg": {
                    "version": "1.0.0",
                    "license": "GPL-3.0",
                },
                "node_modules/mit-pkg": {
                    "version": "2.0.0",
                    "license": "MIT",
                },
            },
        }
        dep_licenses = extract_dep_licenses_package_lock(json.dumps(data))
        # Simulate the classification that check_licenses does
        copyleft_names = []
        for dep in dep_licenses:
            classification = classify_license(normalize_license(dep["license"]))
            if classification == "copyleft":
                copyleft_names.append(dep["name"])
        assert "gpl-pkg" in copyleft_names
        assert "mit-pkg" not in copyleft_names


# ===========================================================================
# Tier 2: End-to-end integration tests
# ===========================================================================


class TestGenerateSbomE2E:
    """generate_sbom: real directory with lockfiles."""

    def test_generate_sbom_e2e(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("flask==3.0.0\nrequests==2.31.0\n")
        (tmp_path / "package.json").write_text('{"name": "test", "version": "1.0.0"}')

        result = generate_sbom(repo_path=str(tmp_path), allowed_roots=[str(tmp_path)])

        assert "error" not in result
        assert "requirements.txt" in result["lockfiles_found"][0]
        assert len(result["dependencies"]) == 2
        assert result["_meta"]["contentTrust"] == "untrusted"
        purls = [d["purl"] for d in result["dependencies"]]
        assert any("pkg:pypi/flask@3.0.0" in purl for purl in purls)

    def test_no_lockfiles_e2e(self, tmp_path):
        result = generate_sbom(repo_path=str(tmp_path), allowed_roots=[str(tmp_path)])

        assert "error" not in result
        assert len(result["dependencies"]) == 0
        assert result["summary"]["total"] == 0

    def test_oversized_lockfile(self, tmp_path):
        huge = "x" * (10 * 1024 * 1024 + 1)
        (tmp_path / "requirements.txt").write_text(huge)

        result = generate_sbom(repo_path=str(tmp_path), allowed_roots=[str(tmp_path)])

        assert "error" not in result
        assert len(result["lockfiles_skipped"]) >= 1
        skip_reasons = [s["reason"] for s in result["lockfiles_skipped"]]
        assert any("exceeds" in r or "limit" in r for r in skip_reasons)

    def test_repo_path_outside_allowed_roots(self, tmp_path):
        result = generate_sbom(repo_path=str(tmp_path), allowed_roots=["/nonexistent/root"])
        assert "error" in result
        assert "outside" in result["error"].lower()


class TestCheckLicensesE2E:
    """check_licenses: real directory with manifest files."""

    def test_check_licenses_e2e(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text('[project]\nlicense = "MIT"')
        package_lock = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root", "version": "1.0.0"},
                "node_modules/express": {
                    "version": "4.18.2",
                    "license": "MIT",
                },
                "node_modules/gpl-lib": {
                    "version": "1.0.0",
                    "license": "GPL-3.0",
                },
            },
        }
        (tmp_path / "package-lock.json").write_text(json.dumps(package_lock))

        result = check_licenses(repo_path=str(tmp_path), allowed_roots=[str(tmp_path)])

        assert "error" not in result
        assert result["project_license"] is not None
        assert "MIT" in result["project_license"]["license"]
        assert result["project_license"]["classification"] == "permissive"
        assert result["summary"]["total"] == 2
        assert result["summary"]["copyleft"] == 1
        assert result["summary"]["permissive"] == 1
        assert len(result["summary"]["copyleft_packages"]) == 1
        assert len(result["compliance_concerns"]) == 1


# ===========================================================================
# Registry tests
# ===========================================================================


class TestToolsRegistered:
    """Both tools registered with correct flags."""

    def test_tools_registered(self):
        specs = get_all_specs()

        for tool_name in ("generate_sbom", "check_licenses"):
            assert tool_name in specs, f"{tool_name} not in registry"
            spec = specs[tool_name]
            assert spec.untrusted is True
            assert spec.annotations is not None
            assert spec.annotations.readOnlyHint is True
