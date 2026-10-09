"""Tests for the MCP adapter. Never executes config content or network."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegisbench.adapters import mcp
from aegisbench.analyzers import graph as graph_analyzer
from aegisbench.rules import broad_permissions


def test_valid_stdio_shape():
    adapted = mcp.adapt_mcp_config(
        {"mcpServers": {"filesystem": {"command": "npx", "args": ["-y", "pkg"]}}},
        source="t.json",
    )
    (tool,) = adapted.fixture.tools
    assert tool.name == "filesystem"
    assert tool.permissions is not None and tool.permissions.commands == ["npx", "-y", "pkg"]
    assert adapted.unsupported == ()
    assert adapted.provenance["tools[0].permissions.commands[0]"] == "mcpServers.filesystem.command"
    assert adapted.provenance["tools[0].permissions.commands[2]"] == "mcpServers.filesystem.args[1]"


def test_missing_command_rejected():
    with pytest.raises(mcp.McpAdapterError, match="command"):
        mcp.adapt_mcp_config({"mcpServers": {"s": {"args": []}}})


def test_wrong_arg_types_rejected():
    with pytest.raises(mcp.McpAdapterError, match="args"):
        mcp.adapt_mcp_config({"mcpServers": {"s": {"command": "x", "args": "nope"}}})
    with pytest.raises(mcp.McpAdapterError, match="mcpServers"):
        mcp.adapt_mcp_config({"mcpServers": ["not", "an", "object"]})
    with pytest.raises(mcp.McpAdapterError, match="object"):
        mcp.adapt_mcp_config(["not", "a", "dict"])  # type: ignore[arg-type]


def test_env_redacted_never_copied():
    adapted = mcp.adapt_mcp_config(
        {"mcpServers": {"s": {"command": "x", "env": {"API_KEY": "sekret"}}}}
    )
    dump = adapted.fixture.model_dump_json()
    assert "sekret" not in dump
    assert "API_KEY" not in dump
    assert any("redacted" in w for w in adapted.warnings)


def test_remote_url_marked_unsupported():
    adapted = mcp.adapt_mcp_config({"mcpServers": {"r": {"url": "https://example.invalid/mcp"}}})
    (tool,) = adapted.fixture.tools
    assert tool.permissions is None  # no invented capabilities
    assert any("url" in u for u in adapted.unsupported)


def test_unknown_keys_marked_not_executed():
    adapted = mcp.adapt_mcp_config(
        {"mcpServers": {"s": {"command": "x", "timeout": 5}}, "otherTop": {}}
    )
    assert any("timeout" in u for u in adapted.unsupported)
    assert any("otherTop" in u for u in adapted.unsupported)
    assert adapted.fixture.tools[0].permissions is not None


def test_duplicate_json_keys_last_wins_documented():
    raw = '{"mcpServers": {"a": {"command": "first"}, "a": {"command": "second"}}}'
    adapted = mcp.adapt_mcp_config(json.loads(raw))
    assert adapted.fixture.tools[0].permissions is not None
    assert adapted.fixture.tools[0].permissions.commands == ["second"]


def test_no_graph_edges_from_adapted_config():
    adapted = mcp.adapt_mcp_config(
        {"mcpServers": {"filesystem": {"command": "npx", "args": ["-y", "pkg"]}}}
    )
    assert graph_analyzer.check(adapted.fixture, "mcp.json") == []


def test_real_mcp_fixtures_adapt_safely():
    for name in ("filesystem_stdio.json", "multi_stdio_env.json", "remote_url.json"):
        data = json.loads(Path(f"benchmark/real_mcp/{name}").read_text(encoding="utf-8"))
        adapted = mcp.adapt_mcp_config(data, source=name)
        dump = adapted.fixture.model_dump_json()
        assert "REDACTED_EXAMPLE" not in dump  # secrets never leak, even fake ones
        assert graph_analyzer.check(adapted.fixture, name) == []  # no invented semantics
        # Baseline runs unchanged on adapted output (smoke test, not a claim).
        broad_permissions.check(adapted.fixture, name)


def test_vscode_servers_container_supported():
    adapted = mcp.adapt_mcp_config(
        {"servers": {"playwright": {"command": "npx", "args": ["-y", "pkg"]}}}
    )
    assert adapted.fixture.tools[0].name == "playwright"
    assert adapted.provenance["tools[0].permissions.commands[0]"] == "servers.playwright.command"


def test_both_containers_rejected():
    with pytest.raises(mcp.McpAdapterError, match="both"):
        mcp.adapt_mcp_config({"mcpServers": {}, "servers": {}})


def test_neither_container_rejected():
    with pytest.raises(mcp.McpAdapterError, match="mcpServers"):
        mcp.adapt_mcp_config({"something": {}})


def test_explicit_stdio_type_accepted():
    adapted = mcp.adapt_mcp_config(
        {"servers": {"s": {"type": "stdio", "command": "node", "args": ["srv.js"]}}}
    )
    assert adapted.fixture.tools[0].permissions is not None


def test_unknown_transport_rejected():
    with pytest.raises(mcp.McpAdapterError, match="type"):
        mcp.adapt_mcp_config({"servers": {"s": {"type": "teleport", "command": "x"}}})


def test_http_type_with_url_is_remote():
    adapted = mcp.adapt_mcp_config({"servers": {"r": {"type": "http", "url": "http://x/mcp"}}})
    assert adapted.fixture.tools[0].permissions is None
    assert any("url" in u for u in adapted.unsupported)


def test_command_plus_url_contradiction_rejected():
    with pytest.raises(mcp.McpAdapterError, match="both"):
        mcp.adapt_mcp_config({"servers": {"s": {"command": "x", "url": "http://x"}}})


def test_headers_oauth_redacted():
    adapted = mcp.adapt_mcp_config(
        {"servers": {"r": {"type": "sse", "url": "https://x/mcp", "headers": {"A": "sekret"}}}}
    )
    dump = adapted.fixture.model_dump_json()
    assert "sekret" not in dump
    assert any("redacted" in w for w in adapted.warnings)


def test_inputs_sandbox_cwd_envfile_unsupported():
    adapted = mcp.adapt_mcp_config(
        {
            "servers": {
                "s": {"command": "x", "cwd": "/tmp", "envFile": ".env", "sandboxEnabled": True}
            },
            "inputs": [{"type": "promptString", "id": "k"}],
            "sandbox": {"filesystem": {"allowWrite": []}},
        }
    )
    joined = " ".join(adapted.unsupported)
    assert "envFile" in joined and "cwd" in joined
    assert "'inputs'" in joined and "'sandbox'" in joined
    assert any("sandbox" in w for w in adapted.warnings)


def test_variables_copied_literally_never_expanded(monkeypatch: pytest.MonkeyPatch):
    adapted = mcp.adapt_mcp_config(
        {"servers": {"s": {"command": "run", "args": ["${workspaceFolder}/x"]}}}
    )
    commands = adapted.fixture.tools[0].permissions.commands
    assert commands is not None and "${workspaceFolder}/x" in commands
    assert any("never expanded" in w for w in adapted.warnings)
    monkeypatch.delenv("workspaceFolder", raising=False)  # nothing to expand from


def test_no_coercion_of_arg_types():
    with pytest.raises(mcp.McpAdapterError, match="args"):
        mcp.adapt_mcp_config({"servers": {"s": {"command": "x", "args": ["ok", 42]}}})
