"""Graph analyzer prototype (Phase 1): GRAPH-CHAIN-001.

Models explicit fixture facts as a directed graph and searches for
predefined data-flow paths:

    sensitive_source -> tool (can_read) -> tool (can_invoke)* -> external_dest

This is a MODELED POTENTIAL path, not proof of exfiltration. Enforcement,
sandboxing, and runtime behavior are not represented.

Design rules for beginners:
- Nodes/edges are created ONLY from explicit fixture IDs. Descriptions are
  never parsed. `file_access` / `network_access` never create edges.
- Every node/edge is marked explicit=True. Paths (findings) are the only
  inferred relationship, built by combining explicit edges.
- Traversal is bounded (MAX_DEPTH), cycle-safe (visited set), and
  deterministic (sorted neighbors, sorted findings).
- Never executes fixture content or makes network requests.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aegisbench.models import (
    FINDING_SCHEMA_VERSION,
    AgentFixture,
    Finding,
    FindingEvidence,
)

RULE_ID = "GRAPH-CHAIN-001"
TITLE = "Potential sensitive-data capability chain to external destination"

EXPLANATION_TEMPLATE = (
    "Modeled data-flow path: {path}. "
    "Each hop is an explicit fixture fact ({hops}). "
    "If the runtime enforces these capabilities literally and tools pass "
    "data as modeled, sensitive data could reach an external destination. "
    "Narrow reads, invokes, or sends_to to break this path."
)
LIMITATIONS = (
    "Static model only, not a confirmed vulnerability or proof of "
    "exfiltration. Edges mirror fixture IDs; the fixture does not describe "
    "enforcement, sandboxing, authentication, data transformation, or "
    "whether invoked tools actually receive sensitive data. "
    "Explicit facts (edges) vs inferred relationships (paths) are "
    "distinguished in the graph record; only paths are inferred."
)

MAX_DEPTH = 6  # maximum edges in one path
MAX_FINDINGS_PER_FIXTURE = 10

NodeKind = str  # "tool" | "permission" | "source" | "destination"
EdgeKind = str  # "has_permission" | "can_read" | "can_invoke" | "can_send_to"


@dataclass(frozen=True, order=True)
class Node:
    kind: NodeKind
    key: str  # e.g. "tool:reader", "source:synthetic_hr_db"
    label: str = ""
    explicit: bool = True


@dataclass(frozen=True, order=True)
class Edge:
    src: str  # node key
    dst: str  # node key
    kind: EdgeKind
    field_path: str = ""  # fixture location supporting this edge
    explicit: bool = True


@dataclass(frozen=True)
class Graph:
    nodes: tuple[Node, ...] = ()
    edges: tuple[Edge, ...] = ()
    warnings: tuple[str, ...] = ()
    node_by_key: dict[str, Node] = field(default_factory=dict, compare=False)


def _tool_key(name: str) -> str:
    return f"tool:{name}"


def _source_key(source_id: str) -> str:
    return f"source:{source_id}"


def _dest_key(dest_id: str) -> str:
    return f"destination:{dest_id}"


def build_graph(fixture: AgentFixture) -> Graph:
    """Build explicit nodes/edges from fixture IDs. Deterministic order."""
    nodes: dict[str, Node] = {}
    edges: list[Edge] = []
    warnings: list[str] = []

    # Deduplicate: first occurrence wins, later ones warn and are ignored
    # for graph purposes (keeps analysis deterministic on bad input).
    seen_tools: dict[str, int] = {}  # name -> original index
    for i, tool in enumerate(fixture.tools):
        if tool.name in seen_tools:
            warnings.append(f"Duplicate tool name ignored: {tool.name!r} at tools[{i}]")
            continue
        seen_tools[tool.name] = i
        nodes[_tool_key(tool.name)] = Node(
            kind="tool", key=_tool_key(tool.name), label=tool.name, explicit=True
        )

    seen_sources: set[str] = set()
    sensitive: set[str] = set()
    for src in fixture.data_sources:
        if src.id in seen_sources:
            warnings.append(f"Duplicate data source ignored: {src.id!r}")
            continue
        seen_sources.add(src.id)
        nodes[_source_key(src.id)] = Node(
            kind="source", key=_source_key(src.id), label=src.id, explicit=True
        )
        if src.sensitivity == "sensitive":
            sensitive.add(src.id)

    seen_dests: set[str] = set()
    external: set[str] = set()
    for dst in fixture.destinations:
        if dst.id in seen_dests:
            warnings.append(f"Duplicate destination ignored: {dst.id!r}")
            continue
        seen_dests.add(dst.id)
        nodes[_dest_key(dst.id)] = Node(
            kind="destination", key=_dest_key(dst.id), label=dst.id, explicit=True
        )
        if dst.trust == "external":
            external.add(dst.id)

    # Permission nodes + data-flow edges, in original tool order for
    # deterministic field paths and warnings.
    for i, tool in enumerate(fixture.tools):
        if seen_tools.get(tool.name) != i:
            continue  # duplicate instance, already warned
        perms = tool.permissions
        if perms is None:
            continue
        tkey = _tool_key(tool.name)
        _add_tool_permissions(nodes, edges, tool.name, tkey, i, perms)

        for k, sid in enumerate(perms.reads or []):
            if sid not in seen_sources:
                warnings.append(
                    f"Missing data source reference: {sid!r} at tools[{i}].permissions.reads[{k}]"
                )
                continue
            edges.append(
                Edge(
                    src=_source_key(sid),
                    dst=tkey,
                    kind="can_read",
                    field_path=f"tools[{i}].permissions.reads[{k}]",
                    explicit=True,
                )
            )
        for k, did in enumerate(perms.sends_to or []):
            if did not in seen_dests:
                warnings.append(
                    f"Missing destination reference: {did!r} "
                    f"at tools[{i}].permissions.sends_to[{k}]"
                )
                continue
            edges.append(
                Edge(
                    src=tkey,
                    dst=_dest_key(did),
                    kind="can_send_to",
                    field_path=f"tools[{i}].permissions.sends_to[{k}]",
                    explicit=True,
                )
            )
        for k, target in enumerate(perms.invokes or []):
            if target not in seen_tools:
                warnings.append(
                    f"Missing tool reference: {target!r} at tools[{i}].permissions.invokes[{k}]"
                )
                continue
            edges.append(
                Edge(
                    src=tkey,
                    dst=_tool_key(target),
                    kind="can_invoke",
                    field_path=f"tools[{i}].permissions.invokes[{k}]",
                    explicit=True,
                )
            )

    # Deterministic ordering for reproducible output.
    ordered_nodes = tuple(sorted(nodes.values()))
    ordered_edges = tuple(sorted(edges))
    return Graph(
        nodes=ordered_nodes,
        edges=ordered_edges,
        warnings=tuple(warnings),
        node_by_key={n.key: n for n in ordered_nodes},
    )


def _add_tool_permissions(nodes, edges, tool_name, tkey, idx, perms) -> None:
    """Create permission nodes + has_permission edges for one tool."""
    for cap in ("commands", "reads", "sends_to", "invokes"):
        values: list[str] | None = getattr(perms, cap)
        if not values:
            continue
        pkey = f"permission:{tool_name}:{cap}"
        nodes[pkey] = Node(kind="permission", key=pkey, label=cap, explicit=True)
        edges.append(
            Edge(
                src=tkey,
                dst=pkey,
                kind="has_permission",
                field_path=f"tools[{idx}].permissions.{cap}",
                explicit=True,
            )
        )


def _flow_neighbors(graph: Graph) -> dict[str, list[Edge]]:
    """Adjacency for data-flow edges only (can_read/can_invoke/can_send_to)."""
    adj: dict[str, list[Edge]] = {}
    for edge in graph.edges:
        if edge.kind not in ("can_read", "can_invoke", "can_send_to"):
            continue
        adj.setdefault(edge.src, []).append(edge)
    for key in adj:
        adj[key] = sorted(adj[key])
    return adj


def find_paths(graph: Graph, fixture: AgentFixture) -> list[list[Edge]]:
    """All bounded sensitive-source -> external-dest paths (deterministic)."""
    sensitive = {s.id for s in fixture.data_sources if s.sensitivity == "sensitive"}
    external = {d.id for d in fixture.destinations if d.trust == "external"}
    if not sensitive or not external:
        return []
    adj = _flow_neighbors(graph)
    starts = sorted(_source_key(s) for s in sensitive)
    targets = {_dest_key(d) for d in external}

    found: list[list[Edge]] = []

    def _dfs(current: str, path: list[Edge], visited: set[str]) -> None:
        if len(path) > MAX_DEPTH:
            return
        if path and current in targets:
            found.append(list(path))
            return
        if len(path) == MAX_DEPTH:
            return
        for edge in adj.get(current, []):
            if edge.dst in visited:
                continue  # cycle-safe: never revisit a node on this path
            visited.add(edge.dst)
            path.append(edge)
            _dfs(edge.dst, path, visited)
            path.pop()
            visited.remove(edge.dst)

    for start in starts:
        if start not in graph.node_by_key:
            continue
        _dfs(start, [], {start})

    # Deterministic: sort by node-key path, then field paths.
    def _path_sort_key(path: list[Edge]) -> tuple:
        keys = [path[0].src] + [e.dst for e in path] if path else []
        fields = [e.field_path for e in path]
        kinds = [e.kind for e in path]
        return (keys, fields, kinds)

    found.sort(key=_path_sort_key)
    return found


def _compact_path(path: list[Edge]) -> str:
    keys = [path[0].src] + [e.dst for e in path] if path else []
    short = [k.replace("source:", "src:").replace("destination:", "dst:") for k in keys]
    text = "->".join(short)
    return text[:200]


def check_detailed(
    fixture: AgentFixture, relative_file_path: str
) -> list[tuple[Finding, list[Edge]]]:
    """Run GRAPH-CHAIN-001, returning each finding with its edge path."""
    graph = build_graph(fixture)
    paths = find_paths(graph, fixture)
    findings: list[Finding] = []
    paired: list[tuple[Finding, list[Edge]]] = []
    for path in paths[:MAX_FINDINGS_PER_FIXTURE]:
        node_keys = [path[0].src] + [e.dst for e in path]
        hop_fields = [e.field_path for e in path]
        # Last tool before the destination is the most relevant tool name.
        tool_name: str | None = None
        for key in reversed(node_keys):
            if key.startswith("tool:"):
                tool_name = key[len("tool:") :]
                break
        explanation = EXPLANATION_TEMPLATE.format(
            path=" -> ".join(node_keys), hops=", ".join(hop_fields) or "n/a"
        )[:2000]
        finding = Finding(
            schema_version=FINDING_SCHEMA_VERSION,  # type: ignore[arg-type]
            rule_id=RULE_ID,
            title=TITLE,
            severity="high",
            confidence="medium",
            relative_file_path=relative_file_path,
            evidence=FindingEvidence(
                field_path=hop_fields[0] if hop_fields else "",
                matched_value=_compact_path(path),
                tool_name=tool_name,
            ),
            explanation=explanation,
            limitations=LIMITATIONS,
        )
        findings.append(finding)
        paired.append((finding, path))
    paired.sort(
        key=lambda pair: (
            pair[0].relative_file_path,
            pair[0].evidence.field_path,
            pair[0].evidence.matched_value,
        ),
    )
    return paired


def check(fixture: AgentFixture, relative_file_path: str) -> list[Finding]:
    """Run GRAPH-CHAIN-001 against one parsed fixture."""
    return [finding for finding, _ in check_detailed(fixture, relative_file_path)]
