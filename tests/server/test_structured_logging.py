"""Tests for structured logging configuration (_configure_logging)."""

import logging
import os
import re
import subprocess
import sys
import textwrap

import pytest

from codesight_mcp.server import _configure_logging


class TestStructuredLogging:
    """Verify _configure_logging() behaviour: env var precedence, format, idempotency."""

    @pytest.fixture(autouse=True)
    def _clean_logging(self):
        """Save and restore root logger state and env vars."""
        root = logging.getLogger()
        old_handlers = root.handlers[:]
        old_level = root.level
        saved_codesight = os.environ.pop("CODESIGHT_LOG_LEVEL", None)
        saved_log = os.environ.pop("LOG_LEVEL", None)
        yield
        root.handlers = old_handlers
        root.level = old_level
        # Restore env vars
        if saved_codesight is not None:
            os.environ["CODESIGHT_LOG_LEVEL"] = saved_codesight
        else:
            os.environ.pop("CODESIGHT_LOG_LEVEL", None)
        if saved_log is not None:
            os.environ["LOG_LEVEL"] = saved_log
        else:
            os.environ.pop("LOG_LEVEL", None)

    def test_codesight_log_level_controls_verbosity(self):
        """CODESIGHT_LOG_LEVEL=DEBUG sets root logger to DEBUG."""
        os.environ["CODESIGHT_LOG_LEVEL"] = "DEBUG"
        _configure_logging()
        assert logging.getLogger().level == logging.DEBUG

    def test_log_level_fallback(self):
        """LOG_LEVEL=ERROR is used when CODESIGHT_LOG_LEVEL is absent."""
        os.environ["LOG_LEVEL"] = "ERROR"
        _configure_logging()
        assert logging.getLogger().level == logging.ERROR

    def test_codesight_log_level_precedence(self):
        """CODESIGHT_LOG_LEVEL takes precedence over LOG_LEVEL."""
        os.environ["CODESIGHT_LOG_LEVEL"] = "DEBUG"
        os.environ["LOG_LEVEL"] = "ERROR"
        _configure_logging()
        assert logging.getLogger().level == logging.DEBUG

    def test_generic_log_level_restricted(self):
        """LOG_LEVEL=DEBUG (without CODESIGHT_LOG_LEVEL) is restricted to WARNING (ADV-LOW-10)."""
        os.environ["LOG_LEVEL"] = "DEBUG"
        _configure_logging()
        assert logging.getLogger().level == logging.WARNING

    def test_codesight_log_level_allows_debug(self):
        """CODESIGHT_LOG_LEVEL=DEBUG is NOT restricted -- operator opted in explicitly."""
        os.environ["CODESIGHT_LOG_LEVEL"] = "DEBUG"
        _configure_logging()
        assert logging.getLogger().level == logging.DEBUG

    def test_log_format_includes_timestamp(self):
        """Handler formats log records with an ISO-8601-style timestamp."""
        _configure_logging()
        root = logging.getLogger()
        handler = root.handlers[0]
        record = logging.LogRecord(
            name="test",
            level=logging.WARNING,
            pathname="test.py",
            lineno=1,
            msg="hello",
            args=None,
            exc_info=None,
        )
        formatted = handler.format(record)
        assert re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", formatted)

    def test_no_stdout_pollution(self):
        """Log output goes to stderr, not stdout (MCP transport safety)."""
        script = textwrap.dedent("""\
            import os, sys, logging
            os.environ["CODESIGHT_LOG_LEVEL"] = "WARNING"
            from codesight_mcp.server import _configure_logging
            _configure_logging()
            logging.getLogger("test").warning("HELLO_STDERR")
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.stdout == ""
        assert "HELLO_STDERR" in result.stderr

    def test_repeated_config_no_handler_duplication(self):
        """Calling _configure_logging() multiple times does not accumulate handlers."""
        _configure_logging()
        _configure_logging()
        _configure_logging()
        assert len(logging.getLogger().handlers) == 1

    def test_exactly_one_stderr_handler(self):
        """After configuration, root logger has exactly one handler targeting stderr."""
        _configure_logging()
        root = logging.getLogger()
        assert len(root.handlers) == 1
        assert root.handlers[0].stream is sys.stderr

    def test_invalid_codesight_log_level_falls_back(self):
        """CODESIGHT_LOG_LEVEL=INVALID falls back to WARNING."""
        os.environ["CODESIGHT_LOG_LEVEL"] = "INVALID"
        _configure_logging()
        assert logging.getLogger().level == logging.WARNING
