# Real-Schema Scope (MCP adapter v1)

No second adapter is implemented in Phase 3: no new research question
requires one. This note records exactly what the existing adapter does and
does not establish.

## What the adapter supports

- Input: MCP client file config, shape
  `{"mcpServers": {"<name>": {"command", "args"?, "env"?}}}` mapped to one
  tool per server with `permissions.commands = [command, *args]`.
- Per-field provenance (`tools[i]...` to `mcpServers.<name>...`).
- `env` presence reported with redaction (values never copied or analyzed).
- Remote `url` entries and unknown keys explicitly marked unsupported.
- Invalid shapes rejected with errors (`McpAdapterError`).

## Guaranteed vs assumed semantics

- Guaranteed by the verified docs: server keys, `command`/`args`/`env`
  roles, remote connectors being URL+auth based with no static file schema.
- AegisBench assumptions (documented, not schema facts): argv order is
  preserved into `commands`; an exact wildcard command entry would trigger
  the baseline; `reads`/`sends_to`/`invokes` are never populated because
  the MCP file schema declares no such semantics.

## Public examples used (provenance)

Official MCP docs fetched 2026-10-09: quickstart/user (local stdio
`npx filesystem` example) and `2026-07-28/develop/connect-remote-servers`
(URL connectors plus auth). Fixtures in `benchmark/real_mcp/` are faithful
MINIMAL reconstructions with synthetic values (`/tmp/synthetic-*`,
`example.invalid`, redacted fake key) - not copies of user data.

## What the 3/3 result establishes (and does not)

- Establishes: the adapter parses verified shapes without crashing,
  preserves provenance, redacts secrets (verified absent from dumps),
  marks remote entries unsupported, and invents no graph edges
  (0 chain findings is the CORRECT output here).
- Does NOT establish: chain detection on real configs, coverage of the
  MCP ecosystem, transport/auth analysis, or any detection effectiveness.
- Second-schema plan (if ever needed): verify against authoritative docs
  first, write an adapter test plan covering valid/invalid/missing/unknown/
  duplicate/unsupported/provenance cases, then implement narrowly.
