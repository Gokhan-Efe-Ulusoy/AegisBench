"""Adversarial regression tests: redaction, injection, boundaries.

All secrets are synthetic markers. Nothing here executes fixture content,
touches the network, or reads outside temporary directories.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aegisbench import reporter
from aegisbench.adapters import mcp
from aegisbench.cli import app
from aegisbench.models import Finding, FindingEvidence
from aegisbench.pipeline import scan_file, scan_path

runner = CliRunner()
MARKER = "sk-test-SYNTHETIC-SECRET-abc123"


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _mcp_doc(**entry) -> dict:
    return {"mcpServers": {"s": {"command": "x", **entry}}}


# --- secrets across output paths ---


def test_env_secret_absent_from_all_scan_outputs(tmp_path: Path, capsys):
    doc = {"mcpServers": {"s": {"command": "x", "env": {"TOKEN": MARKER}}}}
    target = _write(tmp_path / "m.json", json.dumps(doc))
    outcome = scan_file(target, tmp_path)
    blob = json.dumps(
        {
            "findings": [f.model_dump(mode="json") for f in outcome.findings],
            "details": list(outcome.details),
            "warnings": list(outcome.warnings),
            "unsupported": list(outcome.unsupported),
        }
    )
    assert MARKER not in blob
    assert outcome.status == "partial"  # env warning recorded without the value


def test_header_secret_absent_from_outputs(tmp_path: Path):
    doc = {"servers": {"r": {"type": "sse", "url": "https://x/m", "headers": {"A": MARKER}}}}
    outcome = scan_file(_write(tmp_path / "m.json", json.dumps(doc)), tmp_path)
    blob = json.dumps(
        [f.model_dump(mode="json") for f in outcome.findings] + list(outcome.warnings)
    )
    assert MARKER not in blob


def test_adapter_errors_never_echo_secret_values():
    bad_docs = [
        {"mcpServers": {"s": {"command": "x", "args": ["ok", 1], "env": {"K": MARKER}}}},
        {"mcpServers": {"s": {"command": "x", "env": "not-an-object-" + MARKER}}},
        {"mcpServers": "nope-" + MARKER},
        {"servers": {"s": {"type": "http"}}},  # missing url; marker in name below
    ]
    for doc in bad_docs:
        try:
            mcp.adapt_mcp_config(doc, source="t.json")
        except mcp.McpAdapterError as exc:
            assert MARKER not in str(exc)
        else:
            raise AssertionError(f"expected rejection for {doc}")
    # Secret inside a value that fails command validation.
    with pytest.raises(mcp.McpAdapterError) as info:
        mcp.adapt_mcp_config({"mcpServers": {"s": {"command": ""}, "x": MARKER}})
    assert MARKER not in str(info.value)


def test_verbose_outputs_redact_secrets(tmp_path: Path):
    doc = {"mcpServers": {"s": {"command": "x", "env": {"TOKEN": MARKER}}}}
    target = _write(tmp_path / "m.json", json.dumps(doc))
    text = runner.invoke(app, ["scan", str(target), "--format", "text", "--verbose"]).output
    assert MARKER not in text
    second = runner.invoke(app, ["scan", str(target), "--format", "json", "--verbose"])
    payload = json.loads(second.stdout)  # stdout only: statuses go to stderr
    assert MARKER not in json.dumps(payload)
    assert "Partial" in second.stderr  # statuses are reported, just not on stdout


def test_no_environment_expansion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AEGISBENCH_TEST_MARKER", "expanded-sekret-value")
    doc = _mcp_doc(args=["${AEGISBENCH_TEST_MARKER}/bin"])
    outcome = scan_file(_write(tmp_path / "m.json", json.dumps(doc)), tmp_path)
    blob = json.dumps([f.model_dump(mode="json") for f in outcome.findings])
    assert "expanded-sekret-value" not in blob
    assert any("never expanded" in w for w in outcome.warnings)
    # The literal reference survives normalization (proven by the adapter).
    adapted = mcp.adapt_mcp_config(doc)
    commands = adapted.fixture.tools[0].permissions.commands
    assert commands is not None and "${AEGISBENCH_TEST_MARKER}/bin" in commands


# --- unknown fields never become edges ---


def test_unknown_fields_no_edges_no_findings(tmp_path: Path):
    doc = {
        "schema_version": "1.1",
        "tools": [{"name": "t", "permissions": {"commands": ["ls"]}, "evil": True}],
    }
    # Extra tool key is a schema violation -> rejected, never analyzed.
    outcome = scan_file(_write(tmp_path / "a.json", json.dumps(doc)), tmp_path)
    assert outcome.status == "rejected"
    assert outcome.findings == ()


def test_unknown_mcp_keys_ignored_with_warning(tmp_path: Path):
    doc = {"mcpServers": {"s": {"command": "x", "teleport": True}}}
    outcome = scan_file(_write(tmp_path / "m.json", json.dumps(doc)), tmp_path)
    assert outcome.status == "partial"
    assert outcome.findings == ()
    assert any("teleport" in u for u in outcome.unsupported)


# --- malformed / type surprises ---


@pytest.mark.parametrize(
    "text",
    ["", "   ", "null", "42", '"str"', "[1]", "{invalid}"],
)
def test_malformed_and_type_surprises_rejected(tmp_path: Path, text: str):
    outcome = scan_file(_write(tmp_path / "a.json", text), tmp_path)
    assert outcome.status == "rejected", text
    assert outcome.findings == ()


def test_duplicate_tools_first_wins_deterministic(tmp_path: Path):
    doc = {
        "schema_version": "1.1",
        "tools": [
            {"name": "dup", "permissions": {"reads": ["s"]}},
            {"name": "dup", "permissions": {"sends_to": ["d"]}},
        ],
        "data_sources": [{"id": "s", "sensitivity": "sensitive"}],
        "destinations": [{"id": "d", "trust": "external"}],
    }
    first = scan_file(_write(tmp_path / "a.json", json.dumps(doc)), tmp_path)
    second = scan_file(tmp_path / "a.json", tmp_path)
    assert first.findings == ()  # first instance has no send path
    assert first.findings == second.findings
    assert first.warnings and "Duplicate" in first.warnings[0]


def test_dangling_references_no_edges(tmp_path: Path):
    doc = {
        "schema_version": "1.1",
        "tools": [{"name": "t", "permissions": {"reads": ["ghost"], "invokes": ["nobody"]}}],
    }
    outcome = scan_file(_write(tmp_path / "a.json", json.dumps(doc)), tmp_path)
    assert outcome.findings == ()
    assert len(outcome.warnings) == 2


def test_unreadable_file_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    target = _write(tmp_path / "a.json", "{}")

    def _boom(*args, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "read_text", _boom)
    outcome = scan_file(target, tmp_path)
    assert outcome.status == "rejected"
    assert "denied" in outcome.reason


def test_oversized_file_rejected_without_reading(tmp_path: Path):
    big = tmp_path / "a.json"
    big.write_text("x" * (1_000_000 + 5), encoding="utf-8")
    outcome = scan_file(big, tmp_path)
    assert outcome.status == "rejected"
    assert "too large" in outcome.reason


# --- traversal boundaries ---


def test_path_traversal_inside_scan_file(tmp_path: Path):
    inner = tmp_path / "root"
    inner.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"schema_version": "1.0", "tools": []}), encoding="utf-8")
    outcome = scan_file(inner / ".." / "outside.json", inner)
    assert outcome.status == "rejected"
    assert "outside scan root" in outcome.reason


def test_symlink_escape_never_read(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "ok.json").write_text(
        json.dumps({"schema_version": "1.0", "tools": []}), encoding="utf-8"
    )
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({"schema_version": "1.0", "tools": []}), encoding="utf-8")
    link = root / "evil.json"
    try:
        link.symlink_to(secret)
    except OSError:
        pytest.skip("Symlinks not supported on this platform")
    result = scan_path(root)
    assert [o.display_path for o in result.outcomes] == ["ok.json"]
    assert any("symlink escape" in w.lower() for w in result.collector_warnings)


def test_directory_symlink_not_followed_outside(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "ok.json").write_text(
        json.dumps({"schema_version": "1.0", "tools": []}), encoding="utf-8"
    )
    outside = tmp_path / "outside_dir"
    outside.mkdir()
    (outside / "evil.json").write_text(
        json.dumps({"schema_version": "1.0", "tools": []}), encoding="utf-8"
    )
    link = root / "linkdir"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Symlinks not supported on this platform")
    result = scan_path(root)
    assert "evil.json" not in [o.display_path for o in result.outcomes]


# --- terminal injection / escaping ---


def test_control_chars_sanitized_in_text_not_json():
    finding = Finding(
        schema_version="1.0",
        rule_id="BROAD-CMD-001",
        title="t",
        severity="high",
        confidence="high",
        relative_file_path="evil\nfile\x1b[2J.json",
        evidence=FindingEvidence(field_path="tools[0]", matched_value="*\nINJECTED", tool_name="t"),
        explanation="e",
        limitations="l",
    )
    text = reporter.to_text([finding])
    assert "\nINJECTED" not in text and "\x1b" not in text
    assert "?" in text
    payload = json.loads(reporter.to_json([finding]))
    assert payload["findings"][0]["relative_file_path"] == "evil\nfile\x1b[2J.json"


def test_sanitize_replaces_cc_chars():
    assert reporter.sanitize_terminal("a\x00b\x1fc\x7fd") == "a?b?c?d"
    assert reporter.sanitize_terminal("plain-name_1.json") == "plain-name_1.json"


def test_cli_status_lines_sanitized(tmp_path: Path):
    _write(tmp_path / "note.txt", "x")
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert "\x1b" not in result.output
    assert "SKIPPED" in result.output or "Skipped" in result.output


# --- determinism ---


def test_filenames_and_findings_sorted(tmp_path: Path):
    for name in ("z.json", "a.json", "m.json"):
        _write(tmp_path / name, json.dumps({"schema_version": "1.0", "tools": []}))
    result = scan_path(tmp_path)
    assert [o.display_path for o in result.outcomes] == ["a.json", "m.json", "z.json"]
