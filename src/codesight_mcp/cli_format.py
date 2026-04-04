"""CLI output formatters for human-friendly display."""

import json
import re

# Spotlighting markers from core.boundaries
_SPOTLIGHT_RE = re.compile(r'<<<(?:END_)?UNTRUSTED_CODE_[0-9a-f]+>>>\n?')
# Control characters (C0/C1) and all escape sequences (CSI, OSC, etc.)
_CONTROL_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]|\x1b[^\x20-\x7e]*[\x20-\x7e]|\t|\n|\r')


def format_result(result: dict, fmt: str) -> str:
    """Format a tool result dict for CLI output."""
    if fmt == "json":
        return json.dumps(result, indent=2)
    if fmt == "compact":
        return json.dumps(result)
    # Error responses always JSON
    if "error" in result:
        return json.dumps(result, indent=2)
    # table / tsv
    data = _strip_meta(result)
    return _render_table(data) if fmt == "table" else _render_tsv(data)


def _strip_meta(d: dict) -> dict:
    """Return copy without _meta key."""
    return {k: v for k, v in d.items() if k != "_meta"}


def _sanitize_value(value: str) -> str:
    """Strip spotlighting markers and control characters."""
    value = _SPOTLIGHT_RE.sub('', value)
    value = _CONTROL_RE.sub('', value)
    return value


def _truncate(value: str, max_len: int = 60) -> str:
    """Truncate to max_len with ... suffix if needed."""
    if len(value) <= max_len:
        return value
    return value[:max_len - 3] + "..."


def _classify_payload(data: dict):
    """Classify payload shape for table/tsv rendering.

    Returns one of:
    - ("flat", data) — all scalar values
    - ("table", scalars_dict, list_key, rows) — single list-of-dicts
    - ("json", data) — fallback to JSON
    """
    list_keys = [k for k, v in data.items() if isinstance(v, list)]

    if len(list_keys) > 1:
        return ("json", data)

    if len(list_keys) == 1:
        list_key = list_keys[0]
        rows = data[list_key]
        # Only tabularize if ALL items are dicts
        if rows and not all(isinstance(r, dict) for r in rows):
            return ("json", data)
        scalars = {k: v for k, v in data.items() if k != list_key}
        # If any scalar value is a nested dict, fall back to JSON
        # (e.g., lint_index "summary" dict would render as Python repr)
        if any(isinstance(v, dict) for v in scalars.values()):
            return ("json", data)
        return ("table", scalars, list_key, rows)

    # No lists — check if flat scalars or has nested dicts
    has_nested = any(isinstance(v, dict) for v in data.values())
    if has_nested:
        return ("json", data)
    return ("flat", data)


def _render_table(data: dict) -> str:
    """Render as aligned table."""
    classified = _classify_payload(data)

    if classified[0] == "json":
        return json.dumps(data, indent=2)

    if classified[0] == "flat":
        return _render_flat_table(classified[1])

    # table
    _, scalars, _list_key, rows = classified
    return _render_list_table(scalars, rows)


def _render_tsv(data: dict) -> str:
    """Render as TSV."""
    classified = _classify_payload(data)

    if classified[0] == "json":
        return json.dumps(data, indent=2)

    if classified[0] == "flat":
        return _render_flat_tsv(classified[1])

    _, scalars, _list_key, rows = classified
    return _render_list_tsv(scalars, rows)


def _render_flat_table(data: dict) -> str:
    """Render flat key-value pairs as aligned table."""
    if not data:
        return ""
    max_key = max(len(str(k)) for k in data)
    lines = []
    for k, v in data.items():
        val = _truncate(_sanitize_value(str(v)))
        lines.append(f"{str(k):<{max_key + 2}}{val}")
    return "\n".join(lines)


def _render_flat_tsv(data: dict) -> str:
    """Render flat key-value pairs as TSV."""
    lines = []
    for k, v in data.items():
        val = _sanitize_value(str(v))
        lines.append(f"{k}\t{val}")
    return "\n".join(lines)


def _render_list_table(scalars: dict, rows: list[dict]) -> str:
    """Render scalar headers + list-of-dicts as aligned table."""
    lines = []

    # Scalar header lines
    for k, v in scalars.items():
        lines.append(f"{k}: {_sanitize_value(str(v))}")

    if not rows:
        return "\n".join(lines)

    # Determine column order: first-row keys + unseen keys from subsequent rows
    columns = list(rows[0].keys())
    seen = set(columns)
    for row in rows[1:]:
        for k in row:
            if k not in seen:
                columns.append(k)
                seen.add(k)

    # Compute column widths
    widths = {}
    for col in columns:
        header_len = len(col)
        max_val = max(
            (len(_truncate(_sanitize_value(str(row.get(col, ""))))) for row in rows),
            default=0,
        )
        widths[col] = max(header_len, max_val) + 2

    # Header row
    if lines:
        lines.append("")  # blank line between scalars and table
    header = "".join(col.upper().ljust(widths[col]) for col in columns)
    lines.append(header.rstrip())

    # Data rows
    for row in rows:
        cells = []
        for col in columns:
            val = _truncate(_sanitize_value(str(row.get(col, ""))))
            cells.append(val.ljust(widths[col]))
        lines.append("".join(cells).rstrip())

    return "\n".join(lines)


def _render_list_tsv(scalars: dict, rows: list[dict]) -> str:
    """Render scalar headers + list-of-dicts as TSV."""
    lines = []

    # Scalar header lines
    for k, v in scalars.items():
        lines.append(f"{k}: {_sanitize_value(str(v))}")

    if not rows:
        return "\n".join(lines)

    # Determine column order
    columns = list(rows[0].keys())
    seen = set(columns)
    for row in rows[1:]:
        for k in row:
            if k not in seen:
                columns.append(k)
                seen.add(k)

    # Blank line between scalars and data (if scalars exist)
    if lines:
        lines.append("")

    # Header row
    lines.append("\t".join(columns))

    # Data rows — NO truncation for TSV
    for row in rows:
        cells = [_sanitize_value(str(row.get(col, ""))) for col in columns]
        lines.append("\t".join(cells))

    return "\n".join(lines)
