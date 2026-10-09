"""CLI tests: exit codes, JSON schema, determinism. Never executes fixtures."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from aegisbench.cli import app
from aegisbench.models import FINDING_SCHEMA_VERSION, Finding

runner = CliRunner()

SAFE_DIR = Path(__file__).parent / "fixtures" / "safe"
RISKY_DIR = Path(__file__).parent / "fixtures" / "risky"


def test_scan_safe_text_exit_0():
    result = runner.invoke(app, ["scan", str(SAFE_DIR), "--format", "text"])
    assert result.exit_code == 0, result.output
    assert "No findings" in result.output


def test_scan_risky_text_exit_1():
    result = runner.invoke(app, ["scan", str(RISKY_DIR), "--format", "text"])
    assert result.exit_code == 1, result.output
    assert "BROAD-CMD-001" in result.output


def test_scan_risky_json_schema_and_exit_1():
    result = runner.invoke(app, ["scan", str(RISKY_DIR), "--format", "json"])
    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == FINDING_SCHEMA_VERSION
    assert payload["finding_count"] == len(payload["findings"]) == 1
    # Validate each finding against the Pydantic model.
    for item in payload["findings"]:
        Finding.model_validate(item)
    finding = payload["findings"][0]
    assert finding["rule_id"] == "BROAD-CMD-001"
    assert finding["severity"] == "high"
    assert finding["evidence"]["field_path"] == "tools[0].permissions.commands[1]"
    # JSON output must not contain terminal decoration.
    assert "\x1b[" not in result.output


def test_scan_safe_json_exit_0():
    result = runner.invoke(app, ["scan", str(SAFE_DIR), "--format", "json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["finding_count"] == 0
    assert payload["findings"] == []


def test_missing_path_exit_2():
    result = runner.invoke(app, ["scan", "does-not-exist-xyz", "--format", "json"])
    assert result.exit_code == 2


def test_malformed_json_exit_2(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text("{ oops", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    assert result.exit_code == 2


def test_fail_on_none_never_fails():
    result = runner.invoke(app, ["scan", str(RISKY_DIR), "--format", "text", "--fail-on", "none"])
    assert result.exit_code == 0, result.output


def test_deterministic_output(tmp_path: Path):
    first = runner.invoke(app, ["scan", str(RISKY_DIR), "--format", "json"])
    second = runner.invoke(app, ["scan", str(RISKY_DIR), "--format", "json"])
    assert first.output == second.output
    # Multi-file ordering is deterministic too.
    (tmp_path / "b.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "tools": [
                    {"name": "s", "permissions": {"commands": ["*"]}},
                ],
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "a.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "tools": [
                    {"name": "s", "permissions": {"commands": ["*"]}},
                ],
            }
        ),
        encoding="utf-8",
    )
    one = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    two = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    assert one.output == two.output
    payload = json.loads(one.output)
    paths = [f["relative_file_path"] for f in payload["findings"]]
    assert paths == sorted(paths)
