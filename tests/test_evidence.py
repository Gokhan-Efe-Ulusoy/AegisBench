"""Tests for structured graph evidence. Never executes fixture content."""

from __future__ import annotations

from aegisbench import evidence as evidence_mod
from aegisbench.analyzers import graph as graph_analyzer
from aegisbench.models import AgentFixture


def _chain() -> AgentFixture:
    return AgentFixture.model_validate(
        {
            "schema_version": "1.1",
            "tools": [
                {"name": "reader", "permissions": {"reads": ["s1"], "invokes": ["sender"]}},
                {"name": "sender", "permissions": {"sends_to": ["d1"]}},
            ],
            "data_sources": [{"id": "s1", "sensitivity": "sensitive"}],
            "destinations": [{"id": "d1", "trust": "external"}],
        }
    )


def test_detail_has_required_sections():
    fixture = _chain()
    graph = graph_analyzer.build_graph(fixture)
    (path,) = graph_analyzer.find_paths(graph, fixture)
    detail = evidence_mod.describe_path(path, fixture)
    assert detail["rule_id"] == "GRAPH-CHAIN-001"
    assert detail["source"] == {"node": "source:s1", "sensitivity": "sensitive"}
    assert detail["destination"] == {"node": "destination:d1", "trust": "external"}
    assert detail["node_sequence"] == ["source:s1", "tool:reader", "tool:sender", "destination:d1"]
    assert [h["edge"] for h in detail["hops"]] == ["can_read", "can_invoke", "can_send_to"]
    assert all(h["field_path"] for h in detail["hops"])
    assert all(h["provenance"] is None for h in detail["hops"])  # native fixture: no provenance
    for key in ("explicit_facts", "not_established", "review_action"):
        assert detail[key], key
    assert "does not prove" in detail["not_established"]
    assert "narrow" in detail["review_action"]


def test_detail_uses_adapter_provenance():
    fixture = _chain()
    graph = graph_analyzer.build_graph(fixture)
    (path,) = graph_analyzer.find_paths(graph, fixture)
    provenance = {"tools[0].permissions.reads[0]": "mcpServers.reader.command"}
    detail = evidence_mod.describe_path(path, fixture, provenance)
    assert detail["hops"][0]["provenance"] == "mcpServers.reader.command"
    assert detail["hops"][1]["provenance"] is None


def test_detail_deterministic_and_bounded():
    fixture = _chain()
    graph = graph_analyzer.build_graph(fixture)
    (path,) = graph_analyzer.find_paths(graph, fixture)
    first = evidence_mod.describe_path(path, fixture)
    second = evidence_mod.describe_path(path, fixture)
    assert first == second
    assert len(first["hops"]) <= graph_analyzer.MAX_DEPTH


def test_language_never_claims_transmission():
    fixture = _chain()
    graph = graph_analyzer.build_graph(fixture)
    (path,) = graph_analyzer.find_paths(graph, fixture)
    detail = evidence_mod.describe_path(path, fixture)
    text = " ".join(
        [detail["explicit_facts"], detail["not_established"], detail["review_action"]]
    ).lower()
    for forbidden in ("exfiltrates", "transmits data", "reads the data", "will exfiltrate"):
        assert forbidden not in text, forbidden
    # Negated claims are required: must state what is NOT established.
    assert "does not prove" in text
    assert "not established" in detail["not_established"].lower() or "does not prove" in text
