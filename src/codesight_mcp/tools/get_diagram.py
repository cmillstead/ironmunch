"""Generate Mermaid diagrams from code graph data."""

from collections import deque
from typing import Optional

from ..core.boundaries import make_meta, wrap_untrusted_content
from ..parser.graph import CodeGraph
from ._common import RepoContext, prepare_graph_query, timed, elapsed_ms
from .registry import ToolSpec, register


_MAX_NODES = 50
_VALID_TYPES = {"call_graph", "type_hierarchy", "imports", "impact"}


def _escape(label: str) -> str:
    """Escape a label for Mermaid syntax.

    ADV-MED-1: Also replace newlines/carriage returns to prevent Mermaid
    syntax injection via multi-line labels.
    """
    return (label
            .replace('\n', ' ')
            .replace('\r', ' ')
            .replace('"', '#quot;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('|', '#124;')
            .replace('(', '#40;')
            .replace(')', '#41;')
            .replace('[', '#91;')
            .replace(']', '#93;')
            .replace('{', '#123;')
            .replace('}', '#125;')
            .replace(';', '#59;'))


def _node_id(index: int) -> str:
    """Generate a short Mermaid node ID."""
    return f"n{index}"


def _node_label(sym: dict) -> str:
    """Build a display label for a symbol."""
    name = sym.get("name", sym.get("id", "?"))
    kind = sym.get("kind", "")
    if kind in ("function", "method"):
        return f"{name}()"
    return name


def _render_call_graph(
    graph: CodeGraph, symbol_id: str, index, max_depth: int, direction: str,
) -> dict:
    """Render a call graph centered on symbol_id."""
    center = graph.get_symbol(symbol_id)
    if not center:
        return {"error": f"Symbol not found: {symbol_id}"}

    # BFS outward (callees) and inward (callers)
    nodes: dict[str, dict] = {symbol_id: center}
    edges: list[tuple[str, str]] = []

    # Callees (forward)
    queue: deque[tuple[str, int]] = deque([(symbol_id, 0)])
    visited_fwd: set[str] = {symbol_id}
    while queue and len(nodes) < _MAX_NODES:
        current, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for callee_id in graph.get_callees(current):
            if callee_id not in nodes and len(nodes) < _MAX_NODES:
                sym = graph.get_symbol(callee_id)
                if sym:
                    nodes[callee_id] = sym
            if callee_id in nodes:
                edges.append((current, callee_id))
            if callee_id not in visited_fwd and len(nodes) < _MAX_NODES:
                visited_fwd.add(callee_id)
                queue.append((callee_id, depth + 1))

    # Callers (reverse)
    queue = deque([(symbol_id, 0)])
    visited_rev: set[str] = {symbol_id}
    while queue and len(nodes) < _MAX_NODES:
        current, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for caller_id in graph.get_callers(current):
            if caller_id not in nodes and len(nodes) < _MAX_NODES:
                sym = graph.get_symbol(caller_id)
                if sym:
                    nodes[caller_id] = sym
            if caller_id in nodes:
                edges.append((caller_id, current))
            if caller_id not in visited_rev and len(nodes) < _MAX_NODES:
                visited_rev.add(caller_id)
                queue.append((caller_id, depth + 1))

    # Deduplicate edges
    edges = list(set(edges))

    return _build_mermaid(nodes, edges, direction, highlight=symbol_id)


def _render_type_hierarchy(
    graph: CodeGraph, symbol_id: str, index, max_depth: int, direction: str,
) -> dict:
    """Render a type hierarchy centered on symbol_id."""
    center = graph.get_symbol(symbol_id)
    if not center:
        return {"error": f"Symbol not found: {symbol_id}"}

    nodes: dict[str, dict] = {symbol_id: center}
    edges: list[tuple[str, str]] = []
    dash_edges: set[tuple[str, str]] = set()

    hierarchy = graph.get_type_hierarchy(symbol_id)

    # Parents (upward)
    for parent_id in hierarchy["parents"]:
        sym = graph.get_symbol(parent_id) or {"name": parent_id, "kind": "class"}
        nodes[parent_id] = sym
        edges.append((parent_id, symbol_id))

    # Children (downward)
    for child_id in hierarchy["children"]:
        sym = graph.get_symbol(child_id) or {"name": child_id, "kind": "class"}
        nodes[child_id] = sym
        edges.append((symbol_id, child_id))

    # Implements (dashed)
    for iface_id in hierarchy["implements"]:
        sym = graph.get_symbol(iface_id) or {"name": iface_id, "kind": "class"}
        nodes[iface_id] = sym
        dash_edges.add((iface_id, symbol_id))

    for impl_id in hierarchy["implemented_by"]:
        sym = graph.get_symbol(impl_id) or {"name": impl_id, "kind": "class"}
        nodes[impl_id] = sym
        dash_edges.add((symbol_id, impl_id))

    return _build_mermaid(
        nodes, edges, direction, highlight=symbol_id, dash_edges=dash_edges,
    )


def _render_imports(
    graph: CodeGraph, index, path: str, max_depth: int, direction: str,
) -> dict:
    """Render file-level import graph scoped to a path."""
    # Default to LR for import diagrams
    if direction == "TD":
        direction = "LR"

    nodes: dict[str, dict] = {}
    edges: list[tuple[str, str]] = []

    # Find all files matching the path prefix
    seed_files = set()
    for sym in index.symbols:
        file_path = sym.get("file", "")
        if file_path.startswith(path) or file_path == path:
            seed_files.add(file_path)

    # BFS from seed files through imports
    queue: deque[tuple[str, int]] = deque()
    for f in seed_files:
        nodes[f] = {"name": f.rsplit("/", 1)[-1], "kind": "file", "file": f}
        queue.append((f, 0))

    visited: set[str] = set(seed_files)
    while queue and len(nodes) < _MAX_NODES:
        current, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for imported in graph.get_imports_of(current):
            if imported not in nodes:
                nodes[imported] = {"name": imported.rsplit("/", 1)[-1] if "/" in imported else imported, "kind": "file", "file": imported}
            edges.append((current, imported))
            if imported not in visited and len(nodes) < _MAX_NODES:
                visited.add(imported)
                queue.append((imported, depth + 1))

    return _build_mermaid(nodes, edges, direction)


def _render_impact(
    graph: CodeGraph, symbol_id: str, index, max_depth: int, direction: str,
) -> dict:
    """Render impact diagram for a symbol."""
    center = graph.get_symbol(symbol_id)
    if not center:
        return {"error": f"Symbol not found: {symbol_id}"}

    nodes: dict[str, dict] = {symbol_id: center}
    edges: list[tuple[str, str]] = []
    edge_labels: dict[tuple[str, str], str] = {}

    # Multi-relationship BFS tracking parent for correct edges
    # Queue entries: (current, depth, rel, parent)
    queue: deque[tuple[str, int, str, str]] = deque()
    visited: set[str] = {symbol_id}

    # Seed with direct relationships using public type_hierarchy accessor
    hierarchy = graph.get_type_hierarchy(symbol_id)
    for caller_id in graph.get_callers(symbol_id):
        queue.append((caller_id, 1, "calls", symbol_id))
    for child_id in hierarchy["children"]:
        queue.append((child_id, 1, "inherits", symbol_id))
    for impl_id in hierarchy["implemented_by"]:
        queue.append((impl_id, 1, "implements", symbol_id))

    while queue and len(nodes) < _MAX_NODES:
        current, depth, rel, parent = queue.popleft()
        if current in visited:
            continue
        visited.add(current)

        sym = graph.get_symbol(current) or {"name": current, "kind": "unknown"}
        nodes[current] = sym
        edges.append((parent, current))
        edge_labels[(parent, current)] = rel

        if depth < max_depth:
            for caller_id in graph.get_callers(current):
                if caller_id not in visited:
                    queue.append((caller_id, depth + 1, "calls", current))

    return _build_mermaid(
        nodes, edges, direction, highlight=symbol_id, edge_labels=edge_labels,
    )


def _build_mermaid(
    nodes: dict[str, dict],
    edges: list[tuple[str, str]],
    direction: str,
    highlight: Optional[str] = None,
    dash_edges: Optional[set[tuple[str, str]]] = None,
    edge_labels: Optional[dict[tuple[str, str], str]] = None,
) -> dict:
    """Build Mermaid syntax from nodes and edges."""
    dash_edges = dash_edges or set()
    edge_labels = edge_labels or {}

    # Assign short IDs
    id_map: dict[str, str] = {}
    for i, nid in enumerate(nodes):
        id_map[nid] = _node_id(i)

    lines = [f"graph {direction}"]

    # Node declarations
    for nid, sym in nodes.items():
        short = id_map[nid]
        label = _escape(_node_label(sym))
        lines.append(f'    {short}["{label}"]')

    # Edges
    seen_edges: set[tuple[str, str]] = set()
    for src, dst in edges:
        if src not in id_map or dst not in id_map:
            continue
        edge_key = (src, dst)
        if edge_key in seen_edges:
            continue
        seen_edges.add(edge_key)
        s, d = id_map[src], id_map[dst]
        label = edge_labels.get(edge_key, "")
        if edge_key in dash_edges:
            if label:
                lines.append(f'    {s} -.->|{label}| {d}')
            else:
                lines.append(f'    {s} -.-> {d}')
        else:
            if label:
                lines.append(f'    {s} -->|{label}| {d}')
            else:
                lines.append(f'    {s} --> {d}')

    # Highlight
    if highlight and highlight in id_map:
        lines.append(f'    style {id_map[highlight]} fill:#f66')

    mermaid = "\n".join(lines)

    return {
        "mermaid": wrap_untrusted_content(mermaid),
        "node_count": len(nodes),
        "edge_count": len(seen_edges),
    }


def get_diagram(
    repo: str,
    diagram_type: str,
    symbol_id: Optional[str] = None,
    path: Optional[str] = None,
    max_depth: int = 2,
    direction: str = "TD",
    storage_path: Optional[str] = None,
) -> dict:
    """Generate a Mermaid diagram from code graph data.

    Args:
        repo: Repository identifier (owner/repo or just repo name).
        diagram_type: One of 'call_graph', 'type_hierarchy', 'imports', 'impact'.
        symbol_id: Symbol to center diagram on (required for call_graph, type_hierarchy, impact).
        path: File/directory for imports diagram.
        max_depth: BFS depth limit (default 2, max 5).
        direction: Mermaid direction — 'TD' (top-down) or 'LR' (left-right).
        storage_path: Custom storage path.

    Returns:
        Dict with Mermaid syntax, node/edge counts, and _meta envelope.
    """
    start = timed()

    if diagram_type not in _VALID_TYPES:
        return {"error": f"Invalid diagram type: {diagram_type}. Must be one of: {', '.join(sorted(_VALID_TYPES))}"}

    if diagram_type in ("call_graph", "type_hierarchy", "impact") and not symbol_id:
        return {"error": f"symbol_id is required for {diagram_type} diagrams"}

    if diagram_type == "imports" and not path:
        return {"error": "path is required for imports diagrams"}

    if path and ".." in path.split("/"):
        return {"error": "invalid path: traversal not allowed"}

    max_depth = max(1, min(max_depth, 5))
    if direction not in ("TD", "LR"):
        direction = "TD"

    ctx = RepoContext.resolve(repo, storage_path)
    if isinstance(ctx, dict):
        return ctx
    owner, name, index = ctx.owner, ctx.name, ctx.index

    graph = CodeGraph.get_or_build(index.symbols)

    # Dispatch to renderer
    if diagram_type == "call_graph":
        result = _render_call_graph(graph, symbol_id, index, max_depth, direction)
    elif diagram_type == "type_hierarchy":
        result = _render_type_hierarchy(graph, symbol_id, index, max_depth, direction)
    elif diagram_type == "imports":
        result = _render_imports(graph, index, path, max_depth, direction)
    elif diagram_type == "impact":
        result = _render_impact(graph, symbol_id, index, max_depth, direction)

    if "error" in result:
        return result

    ms = elapsed_ms(start)

    return {
        "repo": f"{owner}/{name}",
        "diagram_type": diagram_type,
        "mermaid": result["mermaid"],
        "node_count": result["node_count"],
        "edge_count": result["edge_count"],
        "_meta": {
            **make_meta(source="code_index", trusted=False),
            "timing_ms": ms,
        },
    }


_spec = register(ToolSpec(
    name="get_diagram",
    description=(
        "Generate a Mermaid diagram from code graph data. "
        "Supports call graphs, type hierarchies, import/dependency graphs, "
        "and impact diagrams. Returns Mermaid syntax that can be rendered "
        "in any Mermaid-compatible viewer."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "repo": {
                "type": "string",
                "description": "Repository identifier (owner/repo or just repo name)",
            },
            "type": {
                "type": "string",
                "description": "Diagram type",
                "enum": ["call_graph", "type_hierarchy", "imports", "impact"],
            },
            "symbol_id": {
                "type": "string",
                "description": "Symbol to center diagram on (required for call_graph, type_hierarchy, impact)",
            },
            "path": {
                "type": "string",
                "description": "File or directory for imports diagram",
            },
            "max_depth": {
                "type": "integer",
                "description": "BFS depth limit (default 2, max 5)",
                "default": 2,
            },
            "direction": {
                "type": "string",
                "description": "Diagram direction: 'TD' (top-down) or 'LR' (left-right)",
                "enum": ["TD", "LR"],
                "default": "TD",
            },
        },
        "required": ["repo", "type"],
    },
    handler=lambda args, storage_path: get_diagram(
        repo=args["repo"],
        diagram_type=args["type"],
        symbol_id=args.get("symbol_id"),
        path=args.get("path"),
        max_depth=args.get("max_depth", 2),
        direction=args.get("direction", "TD"),
        storage_path=storage_path,
    ),
    untrusted=True,
    required_args=["repo", "type"],
))
