"""Narrow adapter: MCP client file config -> internal fixture model.

Verified 2026-10-09 against official documentation (see
``docs/mcp_support_matrix.md`` for the per-field matrix):
- Claude Desktop / portable shape (modelcontextprotocol.io quickstart):
  ``{"mcpServers": {"<name>": {"command", "args"?, "env"?}}}``.
- VS Code workspace shape (code.visualstudio.com MCP configuration
  reference): ``{"servers": {"<name>": {"type", "command"?, "args"?,
  "cwd"?, "env"?, "envFile"?, "dev"?, "sandboxEnabled"?}}}`` for stdio,
  and ``{"type": "http"|"sse", "url", "headers"?, "oauth"?}`` for remote.
- Remote URL connectors otherwise have no static file schema and are
  UNSUPPORTED beyond being recorded.

Mapping (documented, minimal):
- Each stdio server becomes one tool named after the server key.
- ``permissions.commands`` = ``[command, *args]`` in order (the literal
  launch argv; the baseline may match an exact ``"*"`` entry only).
- ``env``/``headers`` values are NEVER copied (they may hold secrets).
  Presence is recorded as redacted metadata, never analyzed.
- ``reads`` / ``sends_to`` / ``invokes`` / ``data_sources`` /
  ``destinations`` are never invented: no verified MCP file schema declares
  data-flow semantics, so the graph analyzer (correctly) finds no chain
  paths in adapted configs. Descriptions-as-behavior is refused.
- ``${...}`` variable references are copied literally, never expanded.

Parsing/normalization is separate from analysis: this module returns a
validated ``AgentFixture`` plus provenance, unsupported, and warning lists.
It never executes commands, launches servers, or contacts the network.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from aegisbench.models import AgentFixture

ADAPTER_VERSION = "mcp-adapter v2"
VERIFIED_SOURCES = (
    "https://modelcontextprotocol.io/quickstart/user (portable stdio config); "
    "https://modelcontextprotocol.io/docs/2026-07-28/develop/connect-remote-servers "
    "(remote URL connectors + auth); "
    "https://code.visualstudio.com/docs/agents/reference/mcp-configuration "
    "(VS Code servers format: type/command/args/cwd/env/envFile/dev/sandboxEnabled, "
    "http/sse url/headers/oauth, inputs, sandbox)"
)

_VARIABLE_RE = re.compile(r"\$\{[^}]+\}")

_STDIO_TRANSPORTS = ("stdio",)
_REMOTE_TRANSPORTS = ("http", "sse")
_KNOWN_TRANSPORTS = _STDIO_TRANSPORTS + _REMOTE_TRANSPORTS

# Keys understood per stdio entry; anything else is recorded unsupported.
_STDIO_KEYS = ("type", "command", "args", "cwd", "env", "envFile", "dev", "sandboxEnabled")


class McpAdapterError(ValueError):
    """Raised when an MCP config cannot be adapted safely."""


@dataclass(frozen=True)
class AdaptedConfig:
    fixture: AgentFixture
    provenance: dict[str, str] = field(default_factory=dict)
    unsupported: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


def _is_str_list(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(v, str) for v in value)


def _note_variables(text: str) -> bool:
    return bool(_VARIABLE_RE.search(text))


def adapt_mcp_config(data: object, source: str = "<mcp-config>") -> AdaptedConfig:
    """Adapt a parsed MCP JSON config dict to the internal model."""
    if not isinstance(data, dict):
        raise McpAdapterError(f"{source}: top-level config must be an object")
    unsupported: list[str] = []
    warnings: list[str] = []

    container_key: str | None = None
    for key in ("mcpServers", "servers"):
        if key in data:
            if container_key is not None:
                raise McpAdapterError(
                    f"{source}: contradictory config with both 'mcpServers' and "
                    "'servers' containers; refusing to guess."
                )
            container_key = key
    if container_key is None:
        raise McpAdapterError(f"{source}: config needs a 'mcpServers' or 'servers' object")
    servers = data[container_key]
    if not isinstance(servers, dict):
        raise McpAdapterError(f"{source}: {container_key!r} must be an object")
    if not servers:
        warnings.append(f"No servers declared in {container_key!r}.")

    for key in sorted(data):
        if key in ("mcpServers", "servers"):
            continue
        if key == "inputs":
            unsupported.append(
                "'inputs': sensitive-value prompts are never resolved or executed "
                "(including 'command'-type inputs); entries referencing "
                "unresolved ${input:...} variables are analyzed literally."
            )
        elif key == "sandbox":
            unsupported.append(
                "'sandbox': filesystem/network sandbox rules are not evaluated; "
                "analysis assumes declared launch configuration as written."
            )
        else:
            unsupported.append(f"Top-level key {key!r} is not supported and was ignored.")

    tools: list[dict] = []
    provenance: dict[str, str] = {}
    for index, name in enumerate(sorted(servers)):
        entry = servers[name]
        base = f"{container_key}.{name}"
        if not isinstance(entry, dict):
            raise McpAdapterError(f"{source}: {base} must be an object")
        if not isinstance(name, str) or not name:
            raise McpAdapterError(f"{source}: server name must be a non-empty string")
        transport = entry.get("type")
        if transport is not None and transport not in _KNOWN_TRANSPORTS:
            raise McpAdapterError(f"{source}: {base}.type must be one of {list(_KNOWN_TRANSPORTS)}")
        has_url = "url" in entry
        has_command = "command" in entry
        if has_url and has_command:
            raise McpAdapterError(
                f"{source}: {base} declares both 'url' and 'command'; refusing to guess."
            )
        if transport in _REMOTE_TRANSPORTS or (transport is None and has_url and not has_command):
            _adapt_remote(
                tools, provenance, unsupported, warnings, index, name, base, entry, source
            )
            continue
        _adapt_stdio(tools, provenance, unsupported, warnings, index, name, base, entry, source)

    fixture = AgentFixture.model_validate(
        {"schema_version": "1.1", "agent_name": "mcp-adapted", "tools": tools}
    )
    return AdaptedConfig(
        fixture=fixture,
        provenance=provenance,
        unsupported=tuple(unsupported),
        warnings=tuple(warnings),
    )


def _adapt_remote(tools, provenance, unsupported, warnings, index, name, base, entry, source):
    """Record a remote (URL) server: tool shell with no permissions."""
    url = entry.get("url")
    if not isinstance(url, str) or not url:
        raise McpAdapterError(f"{source}: {base}.url must be a non-empty string")
    # Auth material is never copied; presence only.
    secret_keys = [k for k in ("headers", "oauth") if k in entry]
    for key in sorted(entry):
        if key in ("type", "url"):
            continue
        if key in ("headers", "oauth"):
            warnings.append(f"{base}.{key}: auth material redacted, not analyzed.")
        else:
            unsupported.append(f"{base}.{key}: unsupported key ignored.")
    if secret_keys:
        pass  # presence recorded via warnings above; values never copied.
    unsupported.append(
        f"{base}.url: remote endpoints have no static file schema in the verified "
        "docs; entry yields a tool with no permissions and no graph edges."
    )
    tools.append({"name": name, "description": f"MCP remote entry {name!r} (unsupported)."})
    provenance[f"tools[{index}].name"] = base


def _adapt_stdio(tools, provenance, unsupported, warnings, index, name, base, entry, source):
    """Normalize one stdio server entry to a tool with literal launch argv."""
    command = entry.get("command")
    if not isinstance(command, str) or not command:
        raise McpAdapterError(f"{source}: {base}.command must be a non-empty string")
    args = entry.get("args", [])
    if not _is_str_list(args):
        raise McpAdapterError(f"{source}: {base}.args must be a list of strings")
    for key in sorted(entry):
        if key in _STDIO_KEYS:
            continue
        unsupported.append(f"{base}.{key}: unsupported key ignored.")
    if "env" in entry:
        env = entry["env"]
        if not isinstance(env, dict):
            raise McpAdapterError(f"{source}: {base}.env must be an object")
        # Values may be secrets (API keys) or ${input:...} refs: count only.
        warnings.append(f"{base}.env: {len(env)} variable(s) redacted, not analyzed.")
    for key in ("envFile", "cwd"):
        if key in entry:
            unsupported.append(
                f"{base}.{key}: referenced but never read or expanded; "
                "analysis uses the declared command/args literally."
            )
    if entry.get("sandboxEnabled") is True:
        warnings.append(
            f"{base}.sandboxEnabled: sandbox enforcement is not modeled; "
            "analysis assumes the declared launch configuration as written."
        )
    if "dev" in entry:
        unsupported.append(f"{base}.dev: development-mode settings do not affect analysis.")
    if "inputs" in entry:
        unsupported.append(f"{base}.inputs: never resolved or executed.")
    commands = [command, *args]
    if any(_note_variables(part) for part in commands):
        warnings.append(
            f"{base}: contains ${{...}} variable reference(s), copied literally and never expanded."
        )
    tools.append(
        {
            "name": name,
            "description": f"MCP stdio server {name!r} (adapted from file config).",
            "permissions": {"commands": commands},
        }
    )
    provenance[f"tools[{index}].name"] = base
    for j in range(len(commands)):
        provenance[f"tools[{index}].permissions.commands[{j}]"] = (
            f"{base}.command" if j == 0 else f"{base}.args[{j - 1}]"
        )
