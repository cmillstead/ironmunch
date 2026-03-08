"""Tests for content boundary markers (spotlighting)."""

import re

from codesight_mcp.core.boundaries import wrap_untrusted_content, make_meta


def test_wrap_produces_markers():
    content = "def hello(): pass"
    wrapped = wrap_untrusted_content(content)
    assert "<<<UNTRUSTED_CODE_" in wrapped
    assert "<<<END_UNTRUSTED_CODE_" in wrapped
    assert "def hello(): pass" in wrapped


def test_wrap_uses_random_token():
    """Each call produces a unique token."""
    a = wrap_untrusted_content("code1")
    b = wrap_untrusted_content("code2")
    token_a = re.search(r"UNTRUSTED_CODE_([a-f0-9]+)", a).group(1)
    token_b = re.search(r"UNTRUSTED_CODE_([a-f0-9]+)", b).group(1)
    assert token_a != token_b


def test_wrap_token_is_32_hex():
    wrapped = wrap_untrusted_content("x")
    token = re.search(r"UNTRUSTED_CODE_([a-f0-9]+)", wrapped).group(1)
    assert len(token) == 32


def test_start_and_end_tokens_match():
    wrapped = wrap_untrusted_content("x")
    start = re.search(r"<<<UNTRUSTED_CODE_([a-f0-9]+)>>>", wrapped).group(1)
    end = re.search(r"<<<END_UNTRUSTED_CODE_([a-f0-9]+)>>>", wrapped).group(1)
    assert start == end


def test_make_meta_untrusted():
    meta = make_meta(source="code_index", trusted=False)
    assert meta["contentTrust"] == "untrusted"
    assert "warning" in meta
    assert meta["source"] == "code_index"


def test_make_meta_trusted():
    meta = make_meta(source="index_list", trusted=True)
    assert meta["contentTrust"] == "trusted"
    assert "warning" not in meta
