"""Tests for calculate_symbol_score in the tools._common module (TEST-MED-3)."""

from ironmunch.tools._common import calculate_symbol_score


def test_exact_match_scores_higher_than_partial():
    """Exact name match should score higher than partial match for query 'foo'."""
    query = "foo"
    query_lower = query.lower()
    query_words = set(query_lower.split())

    exact_sym = {
        "name": "foo",
        "signature": "def foo():",
        "summary": "",
        "keywords": [],
        "docstring": "",
    }
    partial_sym = {
        "name": "foobar",
        "signature": "def foobar():",
        "summary": "",
        "keywords": [],
        "docstring": "",
    }

    exact_score = calculate_symbol_score(exact_sym, query_lower, query_words)
    partial_score = calculate_symbol_score(partial_sym, query_lower, query_words)

    assert exact_score > partial_score, (
        f"Exact match score ({exact_score}) should exceed partial match score ({partial_score})"
    )


def test_unrelated_symbol_scores_zero():
    """A symbol unrelated to the query should score 0."""
    query = "foo"
    query_lower = query.lower()
    query_words = set(query_lower.split())

    unrelated_sym = {
        "name": "bar",
        "signature": "def bar():",
        "summary": "computes bar",
        "keywords": ["bar"],
        "docstring": "Computes bar value.",
    }

    score = calculate_symbol_score(unrelated_sym, query_lower, query_words)

    assert score == 0, f"Unrelated symbol should score 0, got {score}"
