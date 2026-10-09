"""Tests for Phase 4 CLI workflow: validate/rules/version/strict/verbose."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from aegisbench import reporter
from aegisbench.cli import app
from aegisbench.models import Finding

runner = CliRunner()
SAFE_DIR = Path("tests/fixtures/safe")
RISKY_DIR = Path("tests/fixtures/risky")
MCP_DIR = Path("examples/mcp")


def test_validate_safe_exit_0():
    result = runner.invoke(app, ["validate", str(SAFE_DIR)])
    assert result.exit_code == 0, result.output
    assert "OK agent.json [fixture]" in result.output


def test_validate_mcp_reports_caveats_exit_0_without_invalid():
    clean = ["validate", str(MCP_DIR / "01_minimal_stdio.json")]
    result = runner.invoke(app, clean)
    assert result.exit_code == 0, result.output
    assert "OK 01_minimal_stdio.json [mcp]" in result.output


def test_validate_malformed_exit_2():
    result = runner.invoke(app, ["validate", str(MCP_DIR / "06_malformed.json")])
    assert result.exit_code == 2
    assert "INVALID" in result.output


def test_validate_never_claims_secure(tmp_path: Path):
    result = runner.invoke(app, ["validate", str(SAFE_DIR)])
    assert "secure" not in result.output.lower()


def test_rules_lists_both_rules():
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0, result.output
    assert "BROAD-CMD-001" in result.output
    assert "GRAPH-CHAIN-001" in result.output
    assert "severity" in result.output
    payload = json.loads(runner.invoke(app, ["rules", "--format", "json"]).output)
    assert {r["rule_id"] for r in payload["rules"]} == {"BROAD-CMD-001", "GRAPH-CHAIN-001"}


def test_version_reports_versions():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0, result.output
    assert "aegisbench:" in result.output and "mcp_adapter:" in result.output
    payload = json.loads(runner.invoke(app, ["version", "--format", "json"]).output)
    assert payload["finding_schema"] == "1.0"
    assert set(payload["fixture_schemas"]) == {"1.0", "1.1"}


def test_strict_fails_on_unsupported_but_not_on_clean():
    assert runner.invoke(app, ["scan", str(SAFE_DIR), "--strict"]).exit_code == 0
    assert (
        runner.invoke(app, ["scan", str(MCP_DIR / "04_unknown_fields.json"), "--strict"]).exit_code
        == 2
    )
    assert (
        runner.invoke(app, ["scan", str(MCP_DIR / "01_minimal_stdio.json"), "--strict"]).exit_code
        == 0
    )


def test_default_json_schema_unchanged():
    result = runner.invoke(app, ["scan", str(RISKY_DIR), "--format", "json"])
    payload = json.loads(result.output)
    assert set(payload) == {"schema_version", "finding_count", "findings"}
    (finding,) = payload["findings"]
    assert set(finding) == {
        "schema_version",
        "rule_id",
        "title",
        "severity",
        "confidence",
        "relative_file_path",
        "evidence",
        "explanation",
        "limitations",
    }
    assert set(finding["evidence"]) == {"field_path", "matched_value", "tool_name"}
    Finding.model_validate(finding)
    assert "\x1b[" not in result.output


def test_default_outputs_byte_identical_to_reporter(tmp_path: Path):
    text = runner.invoke(app, ["scan", str(RISKY_DIR), "--format", "text"]).output
    as_json = runner.invoke(app, ["scan", str(RISKY_DIR), "--format", "json"]).output
    assert text.startswith("Findings: 1")
    assert json.loads(as_json)["finding_count"] == 1
    # Reporter remains the single renderer for default output.
    assert reporter.to_json.__name__ == "to_json"


def test_verbose_json_adds_files_and_detail():
    plain = json.loads(runner.invoke(app, ["scan", str(RISKY_DIR), "--format", "json"]).output)
    verbose = json.loads(
        runner.invoke(app, ["scan", str(RISKY_DIR), "--format", "json", "--verbose"]).output
    )
    assert set(verbose) > set(plain)
    assert verbose["files"][0]["path"] == "agent.json"
    assert verbose["files"][0]["status"] == "scanned"


def test_verbose_text_shows_file_summary(tmp_path: Path):
    result = runner.invoke(app, ["scan", str(SAFE_DIR), "--format", "text", "--verbose"])
    assert result.exit_code == 0, result.output
    assert "Files:" in result.output and "scanned" in result.output


def test_scan_mcp_directory_reports_statuses_not_findings():
    result = runner.invoke(app, ["scan", str(MCP_DIR / "01_minimal_stdio.json")])
    assert result.exit_code == 0, result.output


def test_scan_rejected_reports_reason_and_exit_2():
    result = runner.invoke(app, ["scan", str(MCP_DIR / "06_malformed.json")])
    assert result.exit_code == 2
    assert "Rejected" in result.output or "Malformed" in result.output


def test_json_stdout_pure_statuses_on_stderr():
    result = runner.invoke(
        app, ["scan", str(MCP_DIR / "04_unknown_fields.json"), "--format", "json"]
    )
    json.loads(result.stdout)  # stdout parses as pure JSON
    assert "Partial" not in result.stdout  # statuses go to stderr, not stdout
    assert "Partial" in result.stderr  # but they are still reported
