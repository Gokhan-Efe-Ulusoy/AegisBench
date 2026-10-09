# MCP Support Matrix (`mcp-adapter v2`)

Verified 2026-10-09 against official documentation:

- Portable / Claude Desktop shape (`mcpServers` + `command`/`args`/`env`):
  `https://modelcontextprotocol.io/quickstart/user`
- Remote URL connectors + auth (no static file schema):
  `https://modelcontextprotocol.io/docs/2026-07-28/develop/connect-remote-servers`
- VS Code workspace shape (`servers` + stdio/http/sse fields, `inputs`,
  `sandbox`, variables): `https://code.visualstudio.com/docs/agents/reference/mcp-configuration`
  and `https://code.visualstudio.com/docs/agent-customization/mcp-servers`

Four distinct questions per construct: (1) valid syntax, (2) normalized
form, (3) semantics actually known, (4) security conclusions inferable.
Only file-configuration support is claimed — never MCP protocol support.

## Containers

| Construct | Defined by | Normalized to | Validation | Limits / fixture |
| --- | --- | --- | --- | --- |
| `mcpServers` object (portable/Claude) | Authoritative | Server entries below | Must be object; empty warns | `examples/mcp/01_minimal_stdio.json` |
| `servers` object (VS Code workspace) | Authoritative | Same as `mcpServers` | Must be object | `examples/mcp/02_vscode_servers_format.json` |
| Both containers present | — (contradictory) | Rejected | Hard error, no guessing | `tests/test_mcp_adapter.py` |
| Neither container present | — | Rejected | Hard error | same |
| `inputs` array (top level) | Authoritative | Unsupported note; never resolved/executed (incl. `command`-type inputs) | Must be list if present? No — recorded unsupported without deep validation | `examples/mcp/05_inputs_sandbox_unsupported.json` |
| `sandbox` object (top level) | Authoritative | Unsupported note; rules not evaluated | Recorded only | same |
| Other top-level keys | — | Ignored + unsupported note | Recorded only | `examples/mcp/04_unknown_fields.json` |

## Stdio server entries

| Construct | Defined by | Normalized to | Validation | Limits |
| --- | --- | --- | --- | --- |
| `command` string | Authoritative | `permissions.commands[0]` (literal) | Required, non-empty string | Never executed; `${...}` never expanded (warns) |
| `args` string list | Authoritative | `permissions.commands[1..]` (literal, ordered) | Must be list of strings; absent = `[]` | No coercion: numbers/bools rejected |
| `type: "stdio"` | Authoritative (VS Code) | Accepted marker, stdio path | Must be `stdio`/`http`/`sse` if present | Unknown `type` values rejected |
| `env` object | Authoritative | Redacted: count in warnings only | Must be object; values can be str/num/null per docs | Names AND values never copied; `${input:...}` never resolved |
| `cwd` | Authoritative | Unsupported note; never read/expanded | Recorded only | Working directory not modeled |
| `envFile` | Authoritative | Unsupported note; file never read | Recorded only | Never opens the referenced file |
| `dev` | Authoritative | Unsupported note | Recorded only | No effect on analysis |
| `sandboxEnabled: true` | Authoritative | Warning: enforcement not modeled | Recorded + warning | Analysis assumes declared config as written |
| Unknown server keys | — | Ignored + unsupported note | Recorded only | Never become graph edges |

## Remote server entries

| Construct | Defined by | Normalized to | Validation | Limits |
| --- | --- | --- | --- | --- |
| `type: "http"`/`"sse"` + `url` | Authoritative | Tool with NO permissions | `url` must be non-empty string | No network contact, ever |
| Bare `url` without `type` | Assumption (treated as remote) | Same as above | Same | Documented assumption |
| `command` + `url` together | — (contradictory) | Rejected | Hard error | Refuses to guess transport |
| `headers` / `oauth` | Authoritative | Redacted presence warning; never copied | Presence only | Auth material never analyzed |
| Missing `url` for http/sse type | — | Rejected | Hard error | — |

## What is NOT established

- No `reads`/`sends_to`/`invokes`, data sources, or destinations are ever
  derived: no verified file schema declares data-flow semantics. Graph
  findings on adapted configs are therefore always empty — a correct
  partial-support boundary, not a clean bill of health.
- Descriptions, command strings, filenames, and endpoint URLs are never
  treated as behavior or data flow.
- Sandbox rules, trust prompts, approvals, and runtime permissions are not
  evaluated. A sandboxed server is analyzed identically to an unsandboxed
  one (with an explicit warning).
- Duplicate server names cannot occur in JSON objects (last key wins per
  JSON semantics; covered by unit test, not a fixture).
