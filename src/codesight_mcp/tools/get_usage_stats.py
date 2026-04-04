"""Usage statistics tool."""

from __future__ import annotations

from ..core.boundaries import make_meta
from ..core.usage_logging import UsageLogger
from ._common import timed, elapsed_ms
from mcp.types import ToolAnnotations
from .registry import ToolSpec, register


def get_usage_stats(
    logger: UsageLogger,
    all_tool_names: list[str],
    tool_name: str | None = None,
    storage_path: str | None = None,
    session: str | None = None,
) -> dict:
    """Return usage statistics for all or a single tool.

    Returns:
        Dict with total_calls, per_tool stats, uncalled_tools, session_id, and _meta envelope.
    """
    start = timed()
    effective_session = session or "current"

    if effective_session == "current":
        all_records = logger.get_records()
        session_records = [r for r in all_records if r.session_id == logger._session_id]
        report_session_id = logger._session_id
    elif effective_session == "all":
        session_records = logger.get_records()
        report_session_id = "all"
    else:
        all_records = logger.get_records()
        session_records = [r for r in all_records if r.session_id == effective_session]
        report_session_id = effective_session

    if tool_name is not None:
        session_records = [r for r in session_records if r.tool_name == tool_name]

    # Build per_tool stats from filtered records
    per_tool: dict[str, dict] = {}
    for rec in session_records:
        if rec.tool_name not in per_tool:
            per_tool[rec.tool_name] = {"total_calls": 0, "success_count": 0, "error_count": 0, "_total_ms": 0}
        s = per_tool[rec.tool_name]
        s["total_calls"] += 1
        if rec.success:
            s["success_count"] += 1
        else:
            s["error_count"] += 1
        s["_total_ms"] += rec.response_time_ms

    for s in per_tool.values():
        s["avg_response_time_ms"] = round(s.pop("_total_ms") / s["total_calls"], 1)

    total_calls = sum(s["total_calls"] for s in per_tool.values())

    # uncalled_tools uses ALL records (not session-filtered)
    all_called = {r.tool_name for r in logger.get_records()}
    uncalled_tools = sorted(t for t in all_tool_names if t not in all_called and t != "get_usage_stats")

    ms = elapsed_ms(start)
    return {
        "total_calls": total_calls,
        "per_tool": per_tool,
        "uncalled_tools": uncalled_tools,
        "session_id": report_session_id,
        "_meta": {**make_meta(source="usage_stats", trusted=True), "timing_ms": ms},
    }


def _make_handler(logger_ref, specs_ref):
    def handler(args, storage_path):
        return get_usage_stats(
            logger=logger_ref(),
            all_tool_names=list(specs_ref().keys()),
            tool_name=args.get("tool_name"),
            storage_path=storage_path,
            session=args.get("session"),
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
            "session": {
                "type": "string",
                "description": "Session filter: 'current' (default), 'all', or a specific session ID.",
            },
        },
    },
    handler=lambda args, storage_path: {"error": "Usage logger not initialized"},
    required_args=[],
    annotations=ToolAnnotations(title="Get Usage Stats", readOnlyHint=True, openWorldHint=False),
))
