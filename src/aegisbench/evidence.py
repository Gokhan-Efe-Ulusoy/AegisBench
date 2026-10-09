"""Structured evidence for GRAPH-CHAIN-001 findings (additive detail).

Detection semantics live in `analyzers.graph` and are NOT changed here.
This module re-exposes the already-found paths with node/edge sequences,
source/destination attributes, optional adapter provenance, and fixed
plain-language statements about what is explicit, what is inferred, what
is not established, and what to review. The base `Finding` model and its
JSON schema are untouched; detail is rendered only in verbose modes.
"""

from __future__ import annotations

from aegisbench.analyzers.graph import Edge
from aegisbench.models import AgentFixture

EXPLICIT_FACTS_STATEMENT = (
    "Explicit facts: every hop above names a fixture field that declares "
    "the relationship (a source listed in a tool's reads, a tool named in "
    "another tool's invokes, a destination listed in a tool's sends_to). "
    "The path combining them is the only inferred relationship."
)
NOT_ESTABLISHED_STATEMENT = (
    "Not established: static analysis does not prove the path is reachable "
    "during execution, that invoked tools actually receive sensitive data, "
    "or that data will be transmitted. Enforcement, sandboxing, approvals, "
    "and runtime behavior are not modeled."
)
REVIEW_ACTION_STATEMENT = (
    "Review action: confirm whether each declared capability is intended; "
    "if not, narrow the reads, invokes, or sends_to entries that form this "
    "path, then re-scan."
)


def describe_path(
    path: list[Edge],
    fixture: AgentFixture,
    provenance: dict[str, str] | None = None,
) -> dict:
    """Build a deterministic, bounded detail record for one found path."""
    provenance = provenance or {}
    node_keys = [path[0].src] + [e.dst for e in path] if path else []
    sources = {s.id: s.sensitivity for s in fixture.data_sources}
    dests = {d.id: d.trust for d in fixture.destinations}
    first = node_keys[0] if node_keys else ""
    last = node_keys[-1] if node_keys else ""
    hops = [
        {
            "from": edge.src,
            "to": edge.dst,
            "edge": edge.kind,
            "field_path": edge.field_path,
            "provenance": provenance.get(edge.field_path),
        }
        for edge in path
    ]
    return {
        "rule_id": "GRAPH-CHAIN-001",
        "source": {
            "node": first,
            "sensitivity": sources.get(first.removeprefix("source:"), "unknown"),
        },
        "destination": {
            "node": last,
            "trust": dests.get(last.removeprefix("destination:"), "unknown"),
        },
        "node_sequence": node_keys,
        "hops": hops,
        "explicit_facts": EXPLICIT_FACTS_STATEMENT,
        "not_established": NOT_ESTABLISHED_STATEMENT,
        "review_action": REVIEW_ACTION_STATEMENT,
    }
