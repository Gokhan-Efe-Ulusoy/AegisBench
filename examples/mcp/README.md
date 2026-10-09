# Local MCP example corpus (all values synthetic)

Every file here is synthetic, except where noted as adapted from a public
docs shape (with synthetic values substituted). Nothing here is a real
user configuration, and nothing resembles one beyond the documented keys.
Operational tests assert adaptation behavior only — never detection
accuracy.

| File | Kind | Purpose | Expected `scan` result |
| --- | --- | --- | --- |
| `01_minimal_stdio.json` | Synthetic | Smallest valid stdio config | Scanned, no findings |
| `02_vscode_servers_format.json` | Synthetic | VS Code `servers` + `type: stdio` | Scanned, no findings |
| `03_multi_server_env.json` | Adapted (docs `env` shape, fake key) | Secret redaction | Partial (env warning), secret absent from all output |
| `04_unknown_fields.json` | Synthetic | Unknown server + top-level keys | Partial (unsupported notes), still scanned |
| `05_inputs_sandbox_unsupported.json` | Synthetic | `inputs` + `sandbox` + `sandboxEnabled` | Partial (unsupported + sandbox warning) |
| `06_malformed.json` | Synthetic | Invalid JSON | Rejected, exit 2 |
| `07_remote_only.json` | Synthetic | URL-only remote entry | Partial (unsupported URL), no permissions |
| `08_benign_broad_looking.json` | Synthetic | Permissive-looking args; one argv entry is exactly `*` | Scanned; baseline fires on the literal `*` argv token (exact-match semantics demo, not a vulnerability claim) |
| `09_type_sse_headers.json` | Synthetic | SSE + auth headers | Partial, headers redacted |
| `10_missing_optional.json` | Synthetic | Command only | Scanned, no findings |

Duplicate server names cannot be expressed in JSON (last key wins);
covered by unit test instead. Run: `aegisbench scan examples/mcp`.
