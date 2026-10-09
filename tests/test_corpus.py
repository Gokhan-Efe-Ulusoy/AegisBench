"""Operational corpus tests: adaptation behavior per examples/mcp/README.md."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from aegisbench.cli import app

runner = CliRunner()
CORPUS = Path("examples/mcp")


def _adapt(name: str):
    from aegisbench.adapters import mcp

    data = json.loads((CORPUS / name).read_text(encoding="utf-8"))
    return mcp.adapt_mcp_config(data, source=name)


def test_minimal_and_vscode_shapes_scan_clean():
    for name in (
        "01_minimal_stdio.json",
        "02_vscode_servers_format.json",
        "10_missing_optional.json",
    ):
        adapted = _adapt(name)
        assert adapted.unsupported == ()
        assert adapted.fixture.tools


def test_env_redacted_everywhere():
    adapted = _adapt("03_multi_server_env.json")
    dump = adapted.fixture.model_dump_json()
    assert "REDACTED_EXAMPLE" not in dump
    assert any("redacted" in w for w in adapted.warnings)


def test_unknown_fields_partial_but_usable():
    adapted = _adapt("04_unknown_fields.json")
    assert len(adapted.unsupported) == 3
    assert adapted.fixture.tools[0].permissions is not None


def test_inputs_sandbox_recorded_not_evaluated():
    adapted = _adapt("05_inputs_sandbox_unsupported.json")
    joined = " ".join(adapted.unsupported)
    assert "'inputs'" in joined and "'sandbox'" in joined
    assert any("sandbox" in w for w in adapted.warnings)


def test_remote_has_no_permissions():
    adapted = _adapt("07_remote_only.json")
    assert adapted.fixture.tools[0].permissions is None


def test_broad_looking_arg_matches_exact_star_only():
    adapted = _adapt("08_benign_broad_looking.json")
    commands = adapted.fixture.tools[0].permissions.commands
    assert commands is not None and "*" in commands
    from aegisbench.rules import broad_permissions

    assert len(broad_permissions.check(adapted.fixture, "08")) == 1  # exact-token semantics


def test_sse_headers_redacted():
    adapted = _adapt("09_type_sse_headers.json")
    assert "REDACTED_EXAMPLE" not in adapted.fixture.model_dump_json()
    assert any("redacted" in w for w in adapted.warnings)


def test_malformed_fails_scan_exit_2():
    result = runner.invoke(app, ["scan", str(CORPUS / "06_malformed.json")])
    assert result.exit_code == 2
