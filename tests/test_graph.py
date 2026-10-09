"""Tests for the graph analyzer. Fixture content is never executed."""

from __future__ import annotations

from aegisbench.analyzers import graph
from aegisbench.models import AgentFixture


def _fx(doc: dict) -> AgentFixture:
    return AgentFixture.model_validate(doc)


def _direct() -> AgentFixture:
    return _fx(
        {
            "schema_version": "1.1",
            "tools": [{"name": "sender", "permissions": {"reads": ["s1"], "sends_to": ["d1"]}}],
            "data_sources": [{"id": "s1", "sensitivity": "sensitive"}],
            "destinations": [{"id": "d1", "trust": "external"}],
        }
    )


def _chain() -> AgentFixture:
    return _fx(
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


def test_node_types_present():
    g = graph.build_graph(_chain())
    kinds = {n.kind for n in g.nodes}
    assert {"tool", "permission", "source", "destination"} <= kinds


def test_edge_types_present():
    g = graph.build_graph(_chain())
    kinds = {e.kind for e in g.edges}
    assert {"has_permission", "can_read", "can_invoke", "can_send_to"} <= kinds


def test_direct_exfil_finding_and_evidence():
    fx = _direct()
    findings = graph.check(fx, "a.json")
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "GRAPH-CHAIN-001"
    assert f.severity == "high" and f.confidence == "medium"
    assert "source:s1" in f.explanation and "destination:d1" in f.explanation
    assert f.evidence.field_path == "tools[0].permissions.reads[0]"
    assert f.evidence.tool_name == "sender"
    assert "Static model only" in f.limitations


def test_chain_finding_lists_all_hops():
    findings = graph.check(_chain(), "a.json")
    assert len(findings) == 1
    assert "tool:reader" in findings[0].explanation
    assert "can_invoke" not in findings[0].explanation  # hops shown as field paths
    assert "invokes" in findings[0].explanation


def test_safe_read_only_no_finding():
    fx = _fx(
        {
            "schema_version": "1.1",
            "tools": [{"name": "r", "permissions": {"reads": ["s1"]}}],
            "data_sources": [{"id": "s1", "sensitivity": "sensitive"}],
        }
    )
    assert graph.check(fx, "a.json") == []


def test_broken_chain_no_finding():
    fx = _fx(
        {
            "schema_version": "1.1",
            "tools": [
                {"name": "r", "permissions": {"reads": ["s1"]}},
                {"name": "s", "permissions": {"sends_to": ["d1"]}},
            ],
            "data_sources": [{"id": "s1", "sensitivity": "sensitive"}],
            "destinations": [{"id": "d1", "trust": "external"}],
        }
    )
    assert graph.check(fx, "a.json") == []


def test_missing_reference_warns_without_edge():
    fx = _fx(
        {
            "schema_version": "1.1",
            "tools": [{"name": "r", "permissions": {"reads": ["ghost"]}}],
            "data_sources": [{"id": "s1", "sensitivity": "sensitive"}],
        }
    )
    g = graph.build_graph(fx)
    assert not [e for e in g.edges if e.kind == "can_read"]
    assert any("Missing data source" in w for w in g.warnings)
    assert graph.check(fx, "a.json") == []


def test_duplicate_tool_first_wins():
    fx = _fx(
        {
            "schema_version": "1.1",
            "tools": [
                {"name": "dup", "permissions": {"reads": ["s1"]}},
                {"name": "dup", "permissions": {"sends_to": ["d1"]}},
            ],
            "data_sources": [{"id": "s1", "sensitivity": "sensitive"}],
            "destinations": [{"id": "d1", "trust": "external"}],
        }
    )
    g = graph.build_graph(fx)
    assert any("Duplicate tool" in w for w in g.warnings)
    # First instance has no send path, so no complete chain.
    assert graph.check(fx, "a.json") == []


def test_cycle_terminates():
    fx = _fx(
        {
            "schema_version": "1.1",
            "tools": [
                {"name": "a", "permissions": {"reads": ["s1"], "invokes": ["b"]}},
                {"name": "b", "permissions": {"invokes": ["a"], "sends_to": ["d1"]}},
            ],
            "data_sources": [{"id": "s1", "sensitivity": "sensitive"}],
            "destinations": [{"id": "d1", "trust": "external"}],
        }
    )
    findings = graph.check(fx, "a.json")
    assert len(findings) == 1  # terminates instead of looping forever


def test_depth_limit_blocks_long_chains():
    tools = [{"name": "t0", "permissions": {"reads": ["s1"], "invokes": ["t1"]}}]
    tools += [{"name": f"t{i}", "permissions": {"invokes": [f"t{i + 1}"]}} for i in range(1, 8)]
    tools.append({"name": "t8", "permissions": {"sends_to": ["d1"]}})
    fx = _fx(
        {
            "schema_version": "1.1",
            "tools": tools,
            "data_sources": [{"id": "s1", "sensitivity": "sensitive"}],
            "destinations": [{"id": "d1", "trust": "external"}],
        }
    )
    # Path needs 9 edges (> MAX_DEPTH=6), so no finding.
    assert graph.check(fx, "a.json") == []


def test_deterministic_evidence_paths():
    first = [f.model_dump_json() for f in graph.check(_chain(), "a.json")]
    second = [f.model_dump_json() for f in graph.check(_chain(), "a.json")]
    assert first == second


def test_legacy_fields_create_no_edges():
    fx = _fx(
        {
            "schema_version": "1.1",
            "tools": [
                {"name": "t", "permissions": {"file_access": ["s1"], "network_access": ["d1"]}}
            ],
            "data_sources": [{"id": "s1", "sensitivity": "sensitive"}],
            "destinations": [{"id": "d1", "trust": "external"}],
        }
    )
    g = graph.build_graph(fx)
    assert not [e for e in g.edges if e.kind in ("can_read", "can_send_to")]
    assert graph.check(fx, "a.json") == []
