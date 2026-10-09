"""Pipeline tests: routing, statuses, secrets, malformed inputs."""

from __future__ import annotations

import json
from pathlib import Path

from aegisbench.pipeline import (
    STATUS_PARTIAL,
    STATUS_REJECTED,
    STATUS_SCANNED,
    STATUS_SKIPPED,
    scan_file,
    scan_path,
)

FIXTURE = {
    "schema_version": "1.1",
    "tools": [{"name": "s", "permissions": {"reads": ["src"], "sends_to": ["dst"]}}],
    "data_sources": [{"id": "src", "sensitivity": "sensitive"}],
    "destinations": [{"id": "dst", "trust": "external"}],
}
MCP = {"mcpServers": {"notes": {"command": "python", "args": ["-m", "srv"]}}}


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_fixture_scanned_with_both_rules(tmp_path: Path):
    src = _write(tmp_path / "a.json", json.dumps(FIXTURE))
    outcome = scan_file(src, tmp_path)
    assert outcome.status == STATUS_SCANNED
    assert outcome.kind == "fixture"
    assert {f.rule_id for f in outcome.findings} == {"GRAPH-CHAIN-001"}
    assert len(outcome.details) == 1


def test_mcp_adapted_with_provenance(tmp_path: Path):
    src = _write(tmp_path / "m.json", json.dumps(MCP))
    outcome = scan_file(src, tmp_path)
    assert outcome.status == STATUS_SCANNED
    assert outcome.kind == "mcp"
    assert outcome.findings == ()


def test_mcp_unsupported_is_partial(tmp_path: Path):
    doc = {"mcpServers": {"s": {"command": "x", "bogus": 1}}}
    outcome = scan_file(_write(tmp_path / "m.json", json.dumps(doc)), tmp_path)
    assert outcome.status == STATUS_PARTIAL
    assert outcome.unsupported


def test_graph_warnings_make_partial(tmp_path: Path):
    doc = dict(FIXTURE)
    doc["tools"] = [
        {"name": "s", "permissions": {"reads": ["missing"], "sends_to": ["dst"]}},
    ]
    outcome = scan_file(_write(tmp_path / "a.json", json.dumps(doc)), tmp_path)
    assert outcome.status == STATUS_PARTIAL
    assert outcome.warnings


def test_malformed_is_rejected(tmp_path: Path):
    outcome = scan_file(_write(tmp_path / "a.json", "{ nope"), tmp_path)
    assert outcome.status == STATUS_REJECTED
    assert "Malformed JSON" in outcome.reason


def test_empty_file_rejected(tmp_path: Path):
    outcome = scan_file(_write(tmp_path / "a.json", "   \n"), tmp_path)
    assert outcome.status == STATUS_REJECTED
    assert "empty" in outcome.reason.lower()


def test_invalid_encoding_rejected(tmp_path: Path):
    target = tmp_path / "a.json"
    target.write_bytes(b'{"a": "\xff\xfe broken"}')
    outcome = scan_file(target, tmp_path)
    assert outcome.status == STATUS_REJECTED


def test_unexpected_top_level_type_rejected(tmp_path: Path):
    outcome = scan_file(_write(tmp_path / "a.json", "[1, 2]"), tmp_path)
    assert outcome.status == STATUS_REJECTED


def test_oversized_rejected(tmp_path: Path):
    big = tmp_path / "a.json"
    big.write_text("x" * (1_000_000 + 1), encoding="utf-8")
    outcome = scan_file(big, tmp_path)
    assert outcome.status == STATUS_REJECTED
    assert "too large" in outcome.reason


def test_non_object_mcp_rejected(tmp_path: Path):
    outcome = scan_file(_write(tmp_path / "a.json", json.dumps({"mcpServers": [1]})), tmp_path)
    assert outcome.status == STATUS_REJECTED


def test_directory_reports_skipped_and_scans_rest(tmp_path: Path):
    _write(tmp_path / "ok.json", json.dumps({"schema_version": "1.0", "tools": []}))
    _write(tmp_path / "notes.md", "# hi")
    result = scan_path(tmp_path)
    by_status = {o.display_path: o.status for o in result.outcomes}
    assert by_status["ok.json"] == STATUS_SCANNED
    assert by_status["notes.md"] == STATUS_SKIPPED


def test_recursive_traversal_supported(tmp_path: Path):
    _write(tmp_path / "sub" / "deep.json", json.dumps({"schema_version": "1.0", "tools": []}))
    result = scan_path(tmp_path)
    assert [o.display_path for o in result.outcomes] == ["sub/deep.json"]


def test_secrets_never_appear_in_outcomes(tmp_path: Path):
    doc = {"mcpServers": {"s": {"command": "x", "env": {"TOKEN": "super-sekret-123"}}}}
    outcome = scan_file(_write(tmp_path / "m.json", json.dumps(doc)), tmp_path)
    blob = json.dumps(
        [f.model_dump(mode="json") for f in outcome.findings]
        + list(outcome.warnings)
        + list(outcome.unsupported)
    )
    assert "super-sekret-123" not in blob


def test_deterministic_across_runs(tmp_path: Path):
    _write(tmp_path / "b.json", json.dumps(FIXTURE))
    _write(tmp_path / "a.json", json.dumps(MCP))
    first = [(o.display_path, o.status, len(o.findings)) for o in scan_path(tmp_path).outcomes]
    second = [(o.display_path, o.status, len(o.findings)) for o in scan_path(tmp_path).outcomes]
    assert first == second == [("a.json", STATUS_SCANNED, 0), ("b.json", STATUS_SCANNED, 1)]
