"""Usage statistics tool."""

from __future__ import annotations

from ..core.boundaries import make_meta
from ..core.usage_logging import UsageLogger
from ._common import timed, elapsed_ms
from .registry import ToolSpec, register


def get_usage_stats(
    logger: UsageLogger,
    all_tool_names: list[str],
    tool_name: str | None = None,
    storage_path: str | None = None,
) -> dict:
    """Return usage statistics for all or a single tool.

    Returns:
        Dict with total_calls, per_tool stats, uncalled_tools, and _meta envelope.
    """
    start = timed()
    per_tool = logger.get_stats()

    if tool_name is not None:
        per_tool = {k: v for k, v in per_tool.items() if k == tool_name}

    total_calls = sum(s["total_calls"] for s in per_tool.values())

    called = set(per_tool.keys())
    uncalled_tools = sorted(
        t for t in all_tool_names
        if t not in called and t != "get_usage_stats"
    )

    ms = elapsed_ms(start)

    return {
        "total_calls": total_calls,
        "per_tool": per_tool,
        "uncalled_tools": uncalled_tools,
        "_meta": {
            **make_meta(source="usage_stats", trusted=True),
            "timing_ms": ms,
        },
    }


def _make_handler(logger_ref, specs_ref):
    def handler(args, storage_path):
        return get_usage_stats(
            logger=logger_ref(),
            all_tool_names=list(specs_ref().keys()),
            tool_name=args.get("tool_name"),
            storage_path=storage_path,
        )
    return handler


_spec = register(ToolSpec(
    name="get_usage_stats",
    description="Usage statistics: per-tool call counts, error rates, avg response times, and uncalled tools.",
    input_schema={
        "type": "object",
        "properties": {
            "tool_name": {
                "type": "string",
                "description": "Optional: filter stats to a single tool name.",
            },
        },
    },
    handler=lambda args, storage_path: {"error": "Usage logger not initialized"},
    required_args=[],
))
