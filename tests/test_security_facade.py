"""Tests for the security facade."""

import tempfile
from pathlib import Path

import pytest

from ironmunch.security import (
    validate_file_access,
    safe_read_file,
    is_secret_file,
    is_binary_file,
    is_binary_content,
    should_exclude_file,
    sanitize_repo_identifier,
    sanitize_signature_for_api,
)
from ironmunch.core.validation import ValidationError


class TestValidateFileAccess:
    def test_valid_file(self):
        with tempfile.TemporaryDirectory() as root:
            f = Path(root) / "src" / "main.py"
            f.parent.mkdir()
            f.touch()
            result = validate_file_access("src/main.py", root)
            assert str(Path(root).resolve()) in result

    def test_traversal_blocked(self):
        with tempfile.TemporaryDirectory() as root:
            with pytest.raises(ValidationError):
                validate_file_access("../../etc/passwd", root)


class TestSafeReadFile:
    def test_read_valid(self):
        with tempfile.TemporaryDirectory() as root:
            f = Path(root) / "hello.py"
            f.write_text("print('hello')", encoding="utf-8")
            content = safe_read_file(str(f), root)
            assert content == "print('hello')"

    def test_read_invalid_utf8(self):
        with tempfile.TemporaryDirectory() as root:
            f = Path(root) / "binary.py"
            f.write_bytes(b"hello \xff world")
            content = safe_read_file(str(f), root)
            assert "hello" in content  # errors="replace" mode

    def test_read_oversized_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            f = Path(root) / "big.py"
            f.write_bytes(b"x" * (600 * 1024))  # 600 KB > 500 KB limit
            with pytest.raises(ValidationError, match="maximum size"):
                safe_read_file(str(f), root)


class TestSecretDetection:
    def test_env_file(self):
        assert is_secret_file(".env")

    def test_pem_file(self):
        assert is_secret_file("cert.pem")

    def test_key_file(self):
        assert is_secret_file("server.key")

    def test_normal_file(self):
        assert not is_secret_file("main.py")

    def test_id_rsa(self):
        assert is_secret_file("id_rsa")


class TestBinaryDetection:
    def test_image(self):
        assert is_binary_file("photo.png")

    def test_executable(self):
        assert is_binary_file("program.exe")

    def test_python(self):
        assert not is_binary_file("main.py")

    def test_binary_content_with_null(self):
        assert is_binary_content(b"hello\x00world")

    def test_text_content(self):
        assert not is_binary_content(b"hello world")


class TestShouldExclude:
    def test_secret_excluded(self):
        assert should_exclude_file(".env") == "secret_file"

    def test_binary_excluded(self):
        assert should_exclude_file("image.png") == "binary_file"

    def test_normal_not_excluded(self):
        assert should_exclude_file("main.py") is None


class TestRepoIdentifier:
    def test_valid(self):
        assert sanitize_repo_identifier("my-repo") == "my-repo"

    def test_valid_with_dots(self):
        assert sanitize_repo_identifier("my.repo") == "my.repo"

    def test_valid_with_underscore(self):
        assert sanitize_repo_identifier("my_repo") == "my_repo"

    def test_traversal_rejected(self):
        with pytest.raises(ValidationError):
            sanitize_repo_identifier("../etc")

    def test_slash_rejected(self):
        with pytest.raises(ValidationError):
            sanitize_repo_identifier("repo/evil")

    def test_null_byte_rejected(self):
        with pytest.raises(ValidationError):
            sanitize_repo_identifier("repo\x00evil")

    def test_empty_rejected(self):
        with pytest.raises(ValidationError):
            sanitize_repo_identifier("")

    def test_space_rejected(self):
        with pytest.raises(ValidationError):
            sanitize_repo_identifier("repo name")

    def test_semicolon_rejected(self):
        with pytest.raises(ValidationError):
            sanitize_repo_identifier("repo;rm -rf /")


class TestSanitizeSignatureForApi:
    def test_password_default_redacted(self):
        sig = 'def connect(host, password="hunter2")'
        result = sanitize_signature_for_api(sig)
        assert "hunter2" not in result
        assert "<REDACTED>" in result

    def test_api_key_prefix_redacted(self):
        sig = 'API_KEY = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"'
        result = sanitize_signature_for_api(sig)
        assert "ghp_" not in result
        assert "<REDACTED>" in result

    def test_sk_ant_prefix_redacted(self):
        sig = 'def call_api(key="sk-ant-api03-abcdefghijklmnopqrst")'
        result = sanitize_signature_for_api(sig)
        assert "sk-ant" not in result

    def test_clean_signature_unchanged(self):
        sig = "def hello(name: str) -> str"
        result = sanitize_signature_for_api(sig)
        assert result == sig

    def test_aws_key_redacted(self):
        sig = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
        result = sanitize_signature_for_api(sig)
        assert "AKIA" not in result


class TestSecretDetectionCaseInsensitive:
    """SEC-MED-3: SECRET_PATTERNS must be case-insensitive."""

    def test_uppercase_env(self):
        assert is_secret_file(".ENV")

    def test_mixed_case_env(self):
        assert is_secret_file(".Env")

    def test_uppercase_pem(self):
        assert is_secret_file("CERT.PEM")

    def test_application_properties(self):
        assert is_secret_file("application.properties")

    def test_p8_key(self):
        assert is_secret_file("AuthKey.p8")

    def test_asc_key(self):
        assert is_secret_file("pubkey.asc")

    def test_appsettings_json(self):
        assert is_secret_file("appsettings.Development.json")

    def test_yarnrc(self):
        assert is_secret_file(".yarnrc.yml")


class TestRepoIdentifierDoubleUnderscore:
    """SEC-MED-5: __ separator must be rejected in repo identifiers."""

    def test_double_underscore_rejected(self):
        with pytest.raises(ValidationError, match="reserved separator"):
            sanitize_repo_identifier("a__b")

    def test_single_underscore_allowed(self):
        assert sanitize_repo_identifier("my_repo") == "my_repo"


class TestRepoIdentifierAsciiOnly:
    """SEC-LOW-2: repo identifiers must be ASCII only."""

    def test_unicode_rejected(self):
        with pytest.raises(ValidationError):
            sanitize_repo_identifier("caf\u00e9")

    def test_ascii_allowed(self):
        assert sanitize_repo_identifier("cafe") == "cafe"

    def test_cjk_rejected(self):
        with pytest.raises(ValidationError):
            sanitize_repo_identifier("\u4e16\u754c")


class TestSafeReadFileSymlink:
    """SEC-MED-1: safe_read_file must not follow symlinks (O_NOFOLLOW)."""

    def test_symlink_to_outside_raises(self):
        import os
        with tempfile.TemporaryDirectory() as root:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as outside:
                outside.write(b"outside content")
                outside_path = outside.name
            try:
                link_path = Path(root) / "link.txt"
                os.symlink(outside_path, link_path)
                with pytest.raises((ValidationError, OSError)):
                    safe_read_file(str(link_path), root)
            finally:
                os.unlink(outside_path)

    def test_normal_file_read_returns_content(self):
        with tempfile.TemporaryDirectory() as root:
            f = Path(root) / "data.txt"
            f.write_text("expected content", encoding="utf-8")
            result = safe_read_file(str(f), root)
            assert result == "expected content"


class TestSanitizeSignatureExtendedPatterns:
    """SEC-MED-2: extended inline secret patterns."""

    def test_postgres_connection_string_redacted(self):
        sig = 'url = "postgres://user:secretpass@host/db"'
        result = sanitize_signature_for_api(sig)
        assert "<REDACTED>" in result
        assert "secretpass" not in result

    def test_bearer_token_redacted(self):
        sig = 'auth = "Bearer eyJabcdefghijklmnopqrstuvwxyz"'
        result = sanitize_signature_for_api(sig)
        assert "<REDACTED>" in result

    def test_stripe_live_key_redacted(self):
        sig = 'key = "sk_live_' + "x" * 24 + '"'
        result = sanitize_signature_for_api(sig)
        assert "<REDACTED>" in result
