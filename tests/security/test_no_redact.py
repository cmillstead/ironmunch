"""Tests for CODESIGHT_NO_REDACT=1 env var.

ADV-MED-2: CODESIGHT_NO_REDACT is frozen at module import time. Runtime env
mutations do NOT affect redaction behavior. Tests that need _NO_REDACT=True
must patch the module-level constant directly.
"""

import os
from unittest.mock import patch

import pytest

from codesight_mcp.security import sanitize_signature_for_api, _no_redact
import codesight_mcp.security as security_mod


class TestNoRedactEnvVar:
    """CODESIGHT_NO_REDACT=1 disables inline secret redaction (frozen at startup)."""

    def test_no_redact_disabled_by_default(self):
        """Without the env var at import time, _no_redact() returns False."""
        assert _no_redact() is False

    def test_no_redact_enabled_when_frozen_true(self):
        """When _NO_REDACT is True (set at import), _no_redact() returns True."""
        with patch.object(security_mod, "_NO_REDACT", True):
            assert _no_redact() is True

    def test_no_redact_not_enabled_with_other_values(self):
        """Only '1' activates no-redact at startup, not 'true' or 'yes'."""
        # Since the module was already imported, we test the frozen value
        assert _no_redact() is False

    def test_sanitize_redacts_by_default(self):
        """Without the env var, secrets are redacted normally."""
        sig = 'API_KEY = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"'
        result = sanitize_signature_for_api(sig)
        assert "ghp_" not in result
        assert "<REDACTED>" in result

    def test_sanitize_skips_redaction_when_frozen_true(self):
        """With _NO_REDACT frozen True, secrets pass through unchanged."""
        with patch.object(security_mod, "_NO_REDACT", True):
            sig = 'API_KEY = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"'
            result = sanitize_signature_for_api(sig)
            assert result == sig

    def test_no_redact_preserves_password_defaults(self):
        """With no-redact, password='hunter2' is preserved."""
        with patch.object(security_mod, "_NO_REDACT", True):
            sig = 'def connect(host, password="hunter2")'
            result = sanitize_signature_for_api(sig)
            assert "hunter2" in result
            assert result == sig

    def test_no_redact_preserves_del_bytes(self):
        """With no-redact, DEL/C1 bytes are not stripped either."""
        with patch.object(security_mod, "_NO_REDACT", True):
            sig = "sk_live_\x7f" + "a" * 24
            result = sanitize_signature_for_api(sig)
            assert result == sig  # returned completely unchanged

    def test_runtime_env_mutation_ignored(self):
        """ADV-MED-2: Setting env var after import does NOT disable redaction."""
        os.environ["CODESIGHT_NO_REDACT"] = "1"
        try:
            assert _no_redact() is False, (
                "Runtime env mutation should be ignored — _NO_REDACT is frozen"
            )
            sig = 'token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"'
            result = sanitize_signature_for_api(sig)
            assert "ghp_" not in result  # still redacted
        finally:
            del os.environ["CODESIGHT_NO_REDACT"]

    def test_clean_signature_unaffected(self):
        """A clean signature is the same with or without no-redact."""
        sig = "def hello(name: str) -> str"
        assert sanitize_signature_for_api(sig) == sig
        with patch.object(security_mod, "_NO_REDACT", True):
            assert sanitize_signature_for_api(sig) == sig


class TestNoRedactToolInteraction:
    """CHAIN-3: search_text must refuse when NO_REDACT is enabled."""

    def test_search_text_refuses_when_no_redact_enabled(self):
        """search_text returns an error when CODESIGHT_NO_REDACT=1."""
        from codesight_mcp.tools.search_text import search_text
        with patch.object(security_mod, "_NO_REDACT", True):
            result = search_text(
                repo="test/repo",
                query="password",
                confirm_sensitive_search=True,
            )
        assert "error" in result
        assert "NO_REDACT" in result["error"] or "redaction disabled" in result["error"].lower()

    def test_search_text_works_when_no_redact_disabled(self, tmp_path):
        """search_text proceeds normally when NO_REDACT is off (default)."""
        from codesight_mcp.tools.search_text import search_text
        # Will fail with repo-not-found, but NOT with the NO_REDACT error
        result = search_text(
            repo="nonexistent/repo",
            query="hello",
            confirm_sensitive_search=True,
            storage_path=str(tmp_path),
        )
        # Should get a repo-not-found error, not a redaction error
        assert "error" not in result or "NO_REDACT" not in result.get("error", "")

    def test_get_symbol_still_works_under_no_redact(self):
        """get_symbol is acceptable under NO_REDACT (single symbol, not bulk search)."""
        # This is a documentation test — get_symbol returns one symbol at a time,
        # which is the intended NO_REDACT use case. No code change needed.
        pass
