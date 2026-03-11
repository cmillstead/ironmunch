"""Tests for the security facade."""

import tempfile
from pathlib import Path

import pytest

from codesight_mcp.security import (
    validate_file_access,
    safe_read_file,
    is_secret_file,
    is_binary_file,
    is_binary_content,
    should_exclude_file,
    sanitize_repo_identifier,
    sanitize_signature_for_api,
)
from codesight_mcp.core.validation import ValidationError


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

    def test_huggingface_token_redacted(self):
        """SEC-MED-1: HuggingFace hf_ tokens must be redacted."""
        # Use concatenation to avoid push protection
        token = "hf_" + "a" * 34
        sig = f'TOKEN = "{token}"'
        result = sanitize_signature_for_api(sig)
        assert token not in result
        assert "<REDACTED>" in result

    def test_npm_token_redacted(self):
        """SEC-MED-1: npm npm_ tokens must be redacted."""
        token = "npm_" + "a" * 36
        sig = f'TOKEN = "{token}"'
        result = sanitize_signature_for_api(sig)
        assert token not in result
        assert "<REDACTED>" in result

    def test_pypi_token_redacted(self):
        """SEC-MED-1: PyPI pypi- tokens must be redacted."""
        token = "pypi-" + "a" * 32
        sig = f'TOKEN = "{token}"'
        result = sanitize_signature_for_api(sig)
        assert token not in result
        assert "<REDACTED>" in result

    def test_google_api_key_redacted(self):
        """SEC-MED-1: Google API keys (AIza prefix) must be redacted."""
        token = "AIza" + "a" * 35
        sig = f'TOKEN = "{token}"'
        result = sanitize_signature_for_api(sig)
        assert token not in result
        assert "<REDACTED>" in result


    def test_azure_connection_string_redacted(self):
        """SEC-MED-2: Azure connection strings must be redacted."""
        sig = 'CONN = "DefaultEndpointsProtocol=https;AccountName=myacct;AccountKey=abc123key=="'
        result = sanitize_signature_for_api(sig)
        assert "AccountKey" not in result
        assert "<REDACTED>" in result

    def test_stripe_restricted_live_key_redacted(self):
        """SEC-MED-2: Stripe restricted live keys must be redacted."""
        token = "rk_live_" + "a" * 24
        sig = f'KEY = "{token}"'
        result = sanitize_signature_for_api(sig)
        assert token not in result
        assert "<REDACTED>" in result

    def test_stripe_restricted_test_key_redacted(self):
        """SEC-MED-2: Stripe restricted test keys must be redacted."""
        token = "rk_test_" + "b" * 24
        sig = f'KEY = "{token}"'
        result = sanitize_signature_for_api(sig)
        assert token not in result
        assert "<REDACTED>" in result

    def test_sendgrid_api_key_redacted(self):
        """SEC-MED-2: SendGrid API keys must be redacted."""
        token = "SG." + "a" * 22 + "." + "b" * 22
        sig = f'KEY = "{token}"'
        result = sanitize_signature_for_api(sig)
        assert token not in result
        assert "<REDACTED>" in result

    def test_twilio_account_sid_redacted(self):
        """SEC-MED-2: Twilio Account SIDs must be redacted."""
        token = "AC" + "a" * 32
        sig = f'SID = "{token}"'
        result = sanitize_signature_for_api(sig)
        assert token not in result
        assert "<REDACTED>" in result

    def test_twilio_auth_token_param_redacted(self):
        """SEC-MED-2: twilio= parameter defaults must be redacted."""
        sig = 'def init(twilio="secret_token_value")'
        result = sanitize_signature_for_api(sig)
        assert "secret_token_value" not in result
        assert "<REDACTED>" in result

    def test_mailgun_key_redacted(self):
        """SEC-MED-2: Mailgun keys must be redacted."""
        token = "key-" + "a" * 32
        sig = f'KEY = "{token}"'
        result = sanitize_signature_for_api(sig)
        assert token not in result
        assert "<REDACTED>" in result


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


class TestContextLinesRedaction:
    """SEC-MED-1: context_before/context_after must redact secrets."""

    def test_context_before_redacts_secret(self, tmp_path):
        """Secret on line before a function must be redacted in context_before."""
        import tempfile
        from codesight_mcp.storage.index_store import IndexStore
        from codesight_mcp.tools.get_symbol import get_symbol

        src = (
            'API_KEY = "sk_live_' + 'x' * 24 + '"\n'
            "def my_func():\n"
            "    return 42\n"
        )
        py_file = tmp_path / "sample.py"
        py_file.write_text(src, encoding="utf-8")

        with tempfile.TemporaryDirectory() as storage:
            store = IndexStore(storage)
            from codesight_mcp.parser import parse_file
            symbols = parse_file(src, "sample.py", "python")
            func_symbols = [s for s in symbols if s.name == "my_func"]
            assert func_symbols, "my_func not parsed"
            store.save_index(
                owner="local", name="testctx",
                source_files=["sample.py"],
                symbols=symbols,
                raw_files={"sample.py": src},
                languages={"python": 1},
            )
            result = get_symbol(
                repo="local/testctx",
                symbol_id=func_symbols[0].id,
                context_lines=1,
                storage_path=storage,
            )
            assert "context_before" in result, "Expected context_before in result"
            cb = result["context_before"]
            assert "sk_live_" not in cb, f"Secret leaked in context_before: {cb!r}"
            assert "REDACTED" in cb, f"Expected REDACTED in context_before: {cb!r}"

    def test_context_after_redacts_secret(self, tmp_path):
        """Secret on line after a function must be redacted in context_after."""
        import tempfile
        from codesight_mcp.storage.index_store import IndexStore
        from codesight_mcp.tools.get_symbol import get_symbol

        src = (
            "def my_func():\n"
            "    return 42\n"
            'SECRET = "sk_live_' + 'y' * 24 + '"\n'
        )
        py_file = tmp_path / "sample2.py"
        py_file.write_text(src, encoding="utf-8")

        with tempfile.TemporaryDirectory() as storage:
            store = IndexStore(storage)
            from codesight_mcp.parser import parse_file
            symbols = parse_file(src, "sample2.py", "python")
            func_symbols = [s for s in symbols if s.name == "my_func"]
            assert func_symbols, "my_func not parsed"
            store.save_index(
                owner="local", name="testctx2",
                source_files=["sample2.py"],
                symbols=symbols,
                raw_files={"sample2.py": src},
                languages={"python": 1},
            )
            result = get_symbol(
                repo="local/testctx2",
                symbol_id=func_symbols[0].id,
                context_lines=1,
                storage_path=storage,
            )
            assert "context_after" in result, "Expected context_after in result"
            ca = result["context_after"]
            assert "sk_live_" not in ca, f"Secret leaked in context_after: {ca!r}"
            assert "REDACTED" in ca, f"Expected REDACTED in context_after: {ca!r}"


class TestSourceContentRedaction:
    """SEC-MED-1: source content returned by get_symbol/get_symbols must redact secrets."""

    def test_get_symbol_redacts_secret_in_source(self, tmp_path):
        """A secret embedded in a function body must be redacted in get_symbol output."""
        import tempfile
        from codesight_mcp.storage.index_store import IndexStore
        from codesight_mcp.tools.get_symbol import get_symbol
        from codesight_mcp.parser import parse_file

        src = (
            "def connect():\n"
            '    api_key = "sk-abc123def456ghi789jkl012mno"\n'
            "    return api_key\n"
        )

        with tempfile.TemporaryDirectory() as storage:
            store = IndexStore(storage)
            symbols = parse_file(src, "client.py", "python")
            func_symbols = [s for s in symbols if s.name == "connect"]
            assert func_symbols, "connect not parsed"

            store.save_index(
                owner="local", name="sectest",
                source_files=["client.py"],
                symbols=symbols,
                raw_files={"client.py": src},
                languages={"python": 1},
            )

            result = get_symbol(
                repo="local/sectest",
                symbol_id=func_symbols[0].id,
                storage_path=storage,
            )

            assert "source" in result, f"Expected source in result: {result}"
            source_val = result["source"]
            assert "sk-abc123def456ghi789jkl012mno" not in source_val, (
                f"Secret leaked in source: {source_val!r}"
            )
            assert "REDACTED" in source_val, (
                f"Expected REDACTED in source: {source_val!r}"
            )

    def test_get_symbols_redacts_secret_in_source(self, tmp_path):
        """A secret embedded in a function body must be redacted in get_symbols output."""
        import tempfile
        from codesight_mcp.storage.index_store import IndexStore
        from codesight_mcp.tools.get_symbol import get_symbols
        from codesight_mcp.parser import parse_file

        src = (
            "def setup():\n"
            '    token = "ghp_' + "a" * 36 + '"\n'
            "    return token\n"
        )

        with tempfile.TemporaryDirectory() as storage:
            store = IndexStore(storage)
            symbols = parse_file(src, "auth.py", "python")
            func_symbols = [s for s in symbols if s.name == "setup"]
            assert func_symbols, "setup not parsed"

            store.save_index(
                owner="local", name="sectest2",
                source_files=["auth.py"],
                symbols=symbols,
                raw_files={"auth.py": src},
                languages={"python": 1},
            )

            result = get_symbols(
                repo="local/sectest2",
                symbol_ids=[func_symbols[0].id],
                storage_path=storage,
            )

            assert "symbols" in result
            assert len(result["symbols"]) == 1
            source_val = result["symbols"][0]["source"]
            assert "ghp_" not in source_val, (
                f"Secret leaked in batch source: {source_val!r}"
            )
            assert "REDACTED" in source_val, (
                f"Expected REDACTED in batch source: {source_val!r}"
            )

    def test_stored_content_preserves_raw_secret(self, tmp_path):
        """Raw content on disk must NOT be redacted (preserve byte offsets/hashes)."""
        import tempfile
        from codesight_mcp.storage.index_store import IndexStore
        from codesight_mcp.parser import parse_file

        secret = "sk-abc123def456ghi789jkl012mno"
        src = (
            "def connect():\n"
            f'    api_key = "{secret}"\n'
            "    return api_key\n"
        )

        with tempfile.TemporaryDirectory() as storage:
            store = IndexStore(storage)
            symbols = parse_file(src, "client.py", "python")
            store.save_index(
                owner="local", name="rawtest",
                source_files=["client.py"],
                symbols=symbols,
                raw_files={"client.py": src},
                languages={"python": 1},
            )

            # Read raw content file directly — it must still contain the secret
            from pathlib import Path
            raw_file = Path(storage) / "local__rawtest" / "client.py"
            raw_content = raw_file.read_text(encoding="utf-8")
            assert secret in raw_content, (
                "Raw stored content must preserve the original secret for byte offset integrity"
            )


class TestQueryEchoSanitization:
    """SEC-LOW-13: query parameter must be sanitized before echoing in response."""

    def test_search_text_query_redacted(self, tmp_path):
        """search_text must not echo a secret token in the query field."""
        import tempfile
        from codesight_mcp.storage.index_store import IndexStore
        from codesight_mcp.tools.search_text import search_text

        src = "x = 1\n"
        with tempfile.TemporaryDirectory() as storage:
            store = IndexStore(storage)
            store.save_index(
                owner="local", name="qtest",
                source_files=["x.py"],
                symbols=[],
                raw_files={"x.py": src},
                languages={"python": 1},
            )
            query = "sk_live_" + "a" * 24
            result = search_text(
                repo="local/qtest",
                query=query,
                storage_path=storage,
            )
            assert "query" in result
            assert "sk_live_" not in result["query"], f"Secret in query echo: {result['query']!r}"

    def test_search_symbols_query_redacted(self, tmp_path):
        """search_symbols must not echo a secret token in the query field."""
        import tempfile
        from codesight_mcp.storage.index_store import IndexStore
        from codesight_mcp.tools.search_symbols import search_symbols

        src = "def foo(): pass\n"
        with tempfile.TemporaryDirectory() as storage:
            store = IndexStore(storage)
            from codesight_mcp.parser import parse_file
            symbols = parse_file(src, "x.py", "python")
            store.save_index(
                owner="local", name="qtest2",
                source_files=["x.py"],
                symbols=symbols,
                raw_files={"x.py": src},
                languages={"python": 1},
            )
            query = "sk_live_" + "b" * 24
            result = search_symbols(repo="local/qtest2", query=query, storage_path=storage)
            assert "query" in result
            assert "sk_live_" not in result["query"], f"Secret in query echo: {result['query']!r}"


class TestGetSymbolVerify:
    """TEST-LOW-1: get_symbol verify=True must detect hash mismatches."""

    def test_verify_true_detects_hash_mismatch(self, tmp_path):
        """When the stored content_hash doesn't match re-read content, content_verified=False."""
        import tempfile
        from codesight_mcp.storage.index_store import IndexStore
        from codesight_mcp.tools.get_symbol import get_symbol
        from codesight_mcp.parser import parse_file

        src = "def my_func():\n    return 42\n"

        with tempfile.TemporaryDirectory() as storage:
            store = IndexStore(storage)
            symbols = parse_file(src, "sample.py", "python")
            func_symbols = [s for s in symbols if s.name == "my_func"]
            assert func_symbols, "my_func not parsed"

            store.save_index(
                owner="local", name="verifytest",
                source_files=["sample.py"],
                symbols=symbols,
                raw_files={"sample.py": src},
                languages={"python": 1},
            )

            sym_id = func_symbols[0].id

            # Corrupt the stored content_hash directly in the index JSON
            import gzip as _gzip
            import json
            from pathlib import Path
            index_path = Path(storage) / "local__verifytest.json.gz"
            assert index_path.exists(), f"Index file not found: {index_path}"

            raw = _gzip.decompress(index_path.read_bytes())
            data = json.loads(raw.decode("utf-8"))
            for sym in data.get("symbols", []):
                if sym.get("id") == sym_id:
                    sym["content_hash"] = "0" * 64  # intentionally wrong hash
            compressed = _gzip.compress(json.dumps(data).encode("utf-8"))
            index_path.write_bytes(compressed)

            result = get_symbol(
                repo="local/verifytest",
                symbol_id=sym_id,
                verify=True,
                storage_path=storage,
            )

            assert "_meta" in result, f"Expected _meta in result: {result}"
            assert "content_verified" in result["_meta"], (
                f"Expected content_verified key when verify=True: {result['_meta']}"
            )
            assert result["_meta"]["content_verified"] is False, (
                f"Expected content_verified=False with corrupt hash, got: {result['_meta']['content_verified']}"
            )


class TestRepoIdentifierLengthCap:
    """ADV-LOW-3: repo identifiers must be rejected when over 100 characters."""

    def test_over_100_chars_rejected(self):
        """A 301-character string of valid chars must raise ValidationError."""
        with pytest.raises(ValidationError, match="too long"):
            sanitize_repo_identifier("a" * 301)

    def test_exactly_100_chars_allowed(self):
        """100 characters is within the limit and must pass."""
        assert sanitize_repo_identifier("a" * 100) == "a" * 100

    def test_101_chars_rejected(self):
        """101 characters just exceeds the limit."""
        with pytest.raises(ValidationError, match="too long"):
            sanitize_repo_identifier("a" * 101)


class TestRepoIdentifierTrailingNewline:
    """ADV-MED-7: trailing newline must be rejected ($ anchor bypass via \\Z fix)."""

    def test_trailing_newline_rejected(self):
        """'repo\\n' must raise ValidationError — $ matches before \\n, \\Z does not."""
        with pytest.raises(ValidationError):
            sanitize_repo_identifier("repo\n")

    def test_embedded_newline_rejected(self):
        """A newline anywhere in the identifier must raise ValidationError."""
        with pytest.raises(ValidationError):
            sanitize_repo_identifier("re\npo")

    def test_trailing_carriage_return_rejected(self):
        """Trailing \\r must also be rejected."""
        with pytest.raises(ValidationError):
            sanitize_repo_identifier("repo\r")

    def test_clean_identifier_still_passes(self):
        """A plain valid identifier must still pass after the \\Z fix."""
        assert sanitize_repo_identifier("my-repo") == "my-repo"


class TestSanitizeSignatureDELBypass:
    """ADV-HIGH-7: DEL (0x7F) and C1 bytes must not allow secrets to bypass redaction."""

    def test_del_byte_in_sk_live_still_redacted(self):
        """sk_live_ with DEL inserted must still be redacted after stripping."""
        # DEL between prefix and suffix breaks _INLINE_SECRET_RE without the strip step
        sig = "sk_live_\x7f" + "a" * 23
        result = sanitize_signature_for_api(sig)
        # After stripping 0x7F, the token becomes sk_live_ + 23 chars = 32 chars total
        # _INLINE_SECRET_RE requires sk_live_[a-zA-Z0-9]{24,} so 23 chars is short.
        # Use 24 chars after DEL to meet the minimum.
        sig2 = "sk_live_\x7f" + "a" * 24
        result2 = sanitize_signature_for_api(sig2)
        assert "<REDACTED>" in result2
        assert "sk_live_" not in result2

    def test_c1_byte_in_sk_live_still_redacted(self):
        """sk_live_ with a C1 control inserted must still be redacted."""
        sig = "sk_live_\x82" + "b" * 24
        result = sanitize_signature_for_api(sig)
        assert "<REDACTED>" in result
        assert "sk_live_" not in result

    def test_del_byte_in_ghp_token_still_redacted(self):
        """ghp_ token with DEL inserted must still be redacted."""
        # ghp_ requires exactly 36 alphanum chars after prefix
        sig = "ghp_\x7f" + "a" * 36
        result = sanitize_signature_for_api(sig)
        assert "<REDACTED>" in result
        assert "ghp_" not in result

    def test_del_byte_in_clean_string_does_not_corrupt(self):
        """A string with only DEL/C1 chars (no secret) must not produce REDACTED."""
        sig = "def foo(\x7fbar: str) -> None"
        result = sanitize_signature_for_api(sig)
        # No secret present — DEL stripped, no REDACTED inserted
        assert "<REDACTED>" not in result
        assert "def foo(" in result

    def test_clean_signature_unaffected(self):
        """A signature with no DEL/C1 and no secret is returned unchanged."""
        sig = "def hello(name: str) -> str"
        assert sanitize_signature_for_api(sig) == sig
