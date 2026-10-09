# Real-schema fixtures (MCP client file config)

Verified 2026-10-09 against official MCP documentation:

- Local stdio shape `{"mcpServers": {"<name>": {"command", "args", "env"}}}`
  with the filesystem `npx` example:
  `https://modelcontextprotocol.io/quickstart/user`
- Remote servers are URL-based Custom Connectors set up through the client
  UI, with OAuth/API-key auth (no static file schema in the verified docs):
  `https://modelcontextprotocol.io/docs/2026-07-28/develop/connect-remote-servers`

These are faithful MINIMAL fixtures with synthetic values (placeholder
paths under `/tmp/synthetic-*`, `example.invalid` URL, redacted fake key),
not copies of user data. No secrets, credentials, or personal paths.

| File | Derivation | Adapter expectation |
| --- | --- | --- |
| `filesystem_stdio.json` | Docs quickstart shape, synthetic path | 1 tool, `commands` = launch argv, no findings |
| `multi_stdio_env.json` | Docs `env` troubleshooting shape | 2 tools, `env` redacted + warned, never analyzed |
| `remote_url.json` | URL-connector concept | Unsupported `url` marked; tool with no permissions |

The MCP file schema declares no `reads`/`sends_to`/`invokes` semantics, so
the graph analyzer is expected to report NO chain paths on adapted configs
— an honest partial-support boundary, not a detection claim. Run:

```powershell
python -m aegisbench.heldout --real-mcp
```
