"""Trace potential data flow paths from user-input sources to dangerous sinks."""

import logging
import os
import shutil
import subprocess
from collections import deque
from pathlib import Path
from typing import Optional

from mcp.types import ToolAnnotations

from ..core.boundaries import make_meta, wrap_untrusted_content
from ..core.validation import is_within
from ..parser.graph import CodeGraph
from ..security_rules import scan_symbols
from ._common import prepare_graph_query, timed, elapsed_ms
from .registry import ToolSpec, register

logger = logging.getLogger(__name__)

_DEFAULT_SOURCE_CALLS = frozenset({
    "input", "readline", "read", "recv", "recvfrom", "getenv",
})

_MAX_TAINT_PATHS = 20


# ---------------------------------------------------------------------------
# Core algorithm (testable without RepoContext)
# ---------------------------------------------------------------------------


def _forward_reachable(graph: CodeGraph, start_id: str, max_depth: int = 10) -> set[str]:
    """BFS over forward call edges (get_callees)."""
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(start_id, 0)])
    while queue:
        sym_id, depth = queue.popleft()
        if sym_id in visited or depth > max_depth:
            continue
        visited.add(sym_id)
        for callee_id in graph.get_callees(sym_id):
            queue.append((callee_id, depth + 1))
    return visited


def _find_sinks(sym_dicts: list[dict], min_severity: str = "high") -> list[dict]:
    """Find sink symbols using the security rule engine."""
    findings, _total, _truncated = scan_symbols(
        sym_dicts, min_severity=min_severity, limit=500,
    )
    return findings


def _trace_taint_from_symbols(
    sym_dicts: list[dict],
    graph: CodeGraph,
    source_calls: Optional[list[str]] = None,
    max_depth: int = 10,
) -> dict:
    """Core taint tracing algorithm operating on symbol dicts and a CodeGraph.

    Args:
        sym_dicts: List of symbol dicts from the index.
        graph: Pre-built CodeGraph instance.
        source_calls: Optional custom source API names. Defaults to
            _DEFAULT_SOURCE_CALLS.
        max_depth: Maximum BFS depth for forward reachability.

    Returns:
        Dict with taint_paths, summary, and limitations (no _meta envelope).
    """
    effective_sources = (
        frozenset(source_calls) if source_calls else _DEFAULT_SOURCE_CALLS
    )
    max_depth = min(max(max_depth, 1), 10)

    # Step 1: Find source symbols (symbols whose calls list contains source APIs)
    source_syms: list[dict] = []
    for sym in sym_dicts:
        sym_calls = sym.get("calls", [])
        if any(call_name in effective_sources for call_name in sym_calls):
            source_syms.append(sym)

    # Step 2: Find sink symbols via scan_symbols + ID mapping
    id_lookup: dict[tuple[str, int, str], str] = {}
    for sym in sym_dicts:
        key = (sym.get("file", ""), sym.get("line", 0), sym.get("name", ""))
        id_lookup[key] = sym.get("id", "")

    sink_findings = _find_sinks(sym_dicts, min_severity="high")
    sink_ids: dict[str, dict] = {}
    for finding in sink_findings:
        key = (finding["file"], finding["line"], finding["symbol"])
        if key in id_lookup:
            sink_ids[id_lookup[key]] = finding

    # Step 3: For each source, forward BFS to find reachable sinks
    # First count total reachable pairs, then collect up to _MAX_TAINT_PATHS
    total_reachable_pairs = 0
    reachable_pairs: list[tuple[dict, str]] = []  # (source_sym, sink_id)
    for source_sym in source_syms:
        source_id = source_sym.get("id", "")
        if not source_id:
            continue
        reachable = _forward_reachable(graph, source_id, max_depth)
        reachable_sinks = reachable & set(sink_ids.keys())
        for sink_id in sorted(reachable_sinks):
            total_reachable_pairs += 1
            if len(reachable_pairs) < _MAX_TAINT_PATHS:
                reachable_pairs.append((source_sym, sink_id))

    taint_paths: list[dict] = []
    for source_sym, sink_id in reachable_pairs:
        source_id = source_sym.get("id", "")

        # Get actual call chain path
        chain_result = graph.get_call_chain(source_id, sink_id, max_depth)
        paths = chain_result.get("paths", [])

        # Determine which source API was matched
        source_api = ""
        for call_name in source_sym.get("calls", []):
            if call_name in effective_sources:
                source_api = call_name
                break

        sink_finding = sink_ids[sink_id]
        sink_sym = graph.get_symbol(sink_id)

        if paths:
            # Use the shortest path
            path_ids = paths[0]
            path_names = []
            for pid in path_ids:
                psym = graph.get_symbol(pid)
                path_names.append(
                    wrap_untrusted_content(psym.get("name", pid) if psym else pid)
                )
        else:
            # No explicit path found, but reachability says it's connected
            path_names = [
                wrap_untrusted_content(source_sym.get("name", source_id)),
                wrap_untrusted_content("..."),
                wrap_untrusted_content(
                    sink_sym.get("name", sink_id) if sink_sym else sink_id
                ),
            ]

        taint_paths.append({
            "source": {
                "name": wrap_untrusted_content(source_sym.get("name", "")),
                "file": wrap_untrusted_content(source_sym.get("file", "")),
                "line": source_sym.get("line", 0),
                "source_api": wrap_untrusted_content(source_api),
            },
            "sink": {
                "name": wrap_untrusted_content(
                    sink_sym.get("name", sink_id) if sink_sym else sink_id
                ),
                "file": wrap_untrusted_content(sink_finding.get("file", "")),
                "line": sink_finding.get("line", 0),
                "sink_rule": wrap_untrusted_content(
                    sink_finding.get("rule_id", "")
                ),
            },
            "path": path_names,
            "path_length": len(path_names),
        })

    return {
        "taint_paths": taint_paths,
        "summary": {
            "sources_found": len(source_syms),
            "sinks_found": len(sink_ids),
            "paths_found": total_reachable_pairs,
            "paths_returned": len(taint_paths),
            "truncated": total_reachable_pairs > _MAX_TAINT_PATHS,
        },
        "limitations": [
            "Function-level reachability, not argument-level data flow",
            "Source/sink matching is based on calls list (bare function names)",
            "Cannot verify if tainted data actually flows through parameters",
        ],
    }


# ---------------------------------------------------------------------------
# Semgrep integration
# ---------------------------------------------------------------------------


def _sanitized_env() -> dict[str, str]:
    """Return a copy of os.environ with sensitive keys removed."""
    sensitive_substrings = {"KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"}
    env = {}
    for key, value in os.environ.items():
        key_upper = key.upper()
        if any(s in key_upper for s in sensitive_substrings):
            continue
        env[key] = value
    return env


def _run_semgrep(
    repo_path: Path,
    allowed_roots: Optional[list[str]],
) -> tuple[bool, list[dict]]:
    """Run semgrep on repo_path if available.

    Returns (semgrep_available, findings_list).
    """
    if not shutil.which("semgrep"):
        return False, []

    # Validate repo_path against allowed_roots
    resolved_path = repo_path.expanduser().resolve()
    if allowed_roots:
        allowed = [Path(root).expanduser().resolve() for root in allowed_roots if root.strip()]
        if not any(is_within(a, resolved_path) or resolved_path == a for a in allowed):
            logger.warning("repo_path %s is outside allowed roots", resolved_path)
            return True, []

    if not resolved_path.is_dir():
        logger.warning("repo_path %s is not a directory", resolved_path)
        return True, []

    try:
        result = subprocess.run(
            [
                "semgrep",
                "--config=p/owasp-top-ten",
                "--json",
                "--quiet",
                str(resolved_path),
            ],
            capture_output=True,
            timeout=120,
            env=_sanitized_env(),
        )
        data = __import__("json").loads(result.stdout)
        raw_findings = data.get("results", [])[:50]

        findings = []
        for raw in raw_findings:
            findings.append({
                "rule_id": wrap_untrusted_content(str(raw.get("check_id", ""))),
                "path": wrap_untrusted_content(str(raw.get("path", ""))),
                "line": raw.get("start", {}).get("line", 0),
                "message": wrap_untrusted_content(
                    str(raw.get("extra", {}).get("message", ""))
                ),
                "severity": wrap_untrusted_content(
                    str(raw.get("extra", {}).get("severity", ""))
                ),
            })
        return True, findings

    except (subprocess.TimeoutExpired, OSError, ValueError) as exc:
        logger.warning("Semgrep execution failed: %s", exc)
        return True, []
    except Exception:
        logger.warning("Semgrep produced unparseable output")
        return True, []


# ---------------------------------------------------------------------------
# Tool handler
# ---------------------------------------------------------------------------


def trace_taint(
    repo: str,
    source_calls: Optional[list[str]] = None,
    max_depth: int = 10,
    semgrep: bool = False,
    repo_path: Optional[str] = None,
    storage_path: Optional[str] = None,
    allowed_roots: Optional[list[str]] = None,
) -> dict:
    """Trace potential data flow paths from user-input functions to dangerous sinks.

    Args:
        repo: Repository identifier (owner/repo or just repo name).
        source_calls: Optional custom source API names.
        max_depth: Maximum BFS depth for forward reachability (default 10, max 10).
        semgrep: Whether to run semgrep OWASP scan if available.
        repo_path: Filesystem path for semgrep scanning.
        storage_path: Custom storage path.
        allowed_roots: Allowed root directories for repo_path validation.

    Returns:
        Dict with taint_paths, summary, semgrep results, and _meta envelope.
    """
    start = timed()

    # Resolve repo and build graph (no specific symbol needed)
    result = prepare_graph_query(repo, symbol_id=None, storage_path=storage_path)
    if isinstance(result, dict):
        return result
    owner, name, index, graph, _sym_info = result

    # Get all symbol dicts
    sym_dicts = index.symbols

    # Run core taint analysis
    core_result = _trace_taint_from_symbols(
        sym_dicts, graph, source_calls=source_calls, max_depth=max_depth,
    )

    # Optional semgrep integration
    semgrep_available = False
    semgrep_findings: list[dict] = []
    if semgrep and repo_path:
        semgrep_available, semgrep_findings = _run_semgrep(
            Path(repo_path), allowed_roots,
        )

    ms = elapsed_ms(start)

    return {
        "repo": f"{owner}/{name}",
        "taint_paths": core_result["taint_paths"],
        "summary": core_result["summary"],
        "semgrep_available": semgrep_available,
        "semgrep_findings": semgrep_findings,
        "limitations": core_result["limitations"],
        "_meta": {
            **make_meta(source="taint_analysis", trusted=False),
            "timing_ms": ms,
        },
    }


# ---------------------------------------------------------------------------
# Handler wrapper + allowed-roots wiring (same pattern as generate_sbom.py)
# ---------------------------------------------------------------------------


def _handle_trace_taint(args: dict, storage_path, *, _allowed_roots_fn=None):
    """Handler that resolves ALLOWED_ROOTS at call time."""
    if _handle_trace_taint._allowed_roots_fn is not None:
        allowed = _handle_trace_taint._allowed_roots_fn()
    else:
        allowed = None
    return trace_taint(
        repo=args["repo"],
        source_calls=args.get("source_calls"),
        max_depth=args.get("max_depth", 10),
        semgrep=args.get("semgrep", False),
        repo_path=args.get("repo_path"),
        storage_path=storage_path,
        allowed_roots=allowed,
    )


_handle_trace_taint._allowed_roots_fn = None


def set_allowed_roots_fn(fn):
    """Set the function that returns ALLOWED_ROOTS. Called by server.py."""
    _handle_trace_taint._allowed_roots_fn = fn


_spec = register(ToolSpec(
    name="trace_taint",
    description=(
        "Trace potential data flow paths from user-input functions "
        "(input, read, recv, getenv) to dangerous API calls (eval, exec, "
        "subprocess). Uses forward BFS reachability on the call graph "
        "intersected with security rule findings. Optionally runs semgrep "
        "OWASP scan if repo_path is provided."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "repo": {
                "type": "string",
                "description": "Repository identifier (owner/repo or just repo name)",
            },
            "source_calls": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Custom source API names to look for in calls lists. "
                    "Defaults to input, readline, read, recv, recvfrom, getenv."
                ),
            },
            "max_depth": {
                "type": "integer",
                "description": "Maximum BFS depth for forward reachability (default 10, max 10)",
                "default": 10,
            },
            "semgrep": {
                "type": "boolean",
                "description": "Run semgrep OWASP scan if available (requires repo_path)",
                "default": False,
            },
            "repo_path": {
                "type": "string",
                "description": "Filesystem path for semgrep scanning",
            },
        },
        "required": ["repo"],
    },
    handler=lambda args, storage_path: _handle_trace_taint(args, storage_path),
    required_args=["repo"],
    untrusted=True,
    annotations=ToolAnnotations(
        title="Trace Taint",
        readOnlyHint=True,
        idempotentHint=True,
        openWorldHint=True,
    ),
))
