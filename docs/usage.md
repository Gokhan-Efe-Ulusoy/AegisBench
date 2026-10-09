# Usage

## Scan a file or directory

```powershell
aegisbench scan ./agent.json
aegisbench scan ./configs --format json
aegisbench scan ./configs --strict
aegisbench scan ./configs --format json --verbose
```

- Single JSON files and directories (recursive) are supported.
- Native fixtures (`schema_version` 1.0/1.1) get baseline + graph checks.
- Supported MCP configs (`mcpServers`/`servers`) are normalized first;
  see `docs/mcp_support_matrix.md`.
- Per-file outcomes (scanned / partial / skipped / rejected) print to
  stderr. `Rejected …` means that file blocked a clean result (exit 2).

## Validate without a verdict

```powershell
aegisbench validate ./mcp.json
```

Checks syntax and normalization only. `OK-WITH-CAVEATS` lists warnings
and unsupported constructs. A valid result never claims security.

## Other commands

```powershell
aegisbench rules            # rule IDs, severity/confidence, scope
aegisbench version          # package, analyzer, adapter, schema versions
```

## Exit codes

| Code | Meaning |
| ---- | ------- |
| 0 | Completed; no findings met `--fail-on` (default `medium`); `validate` clean |
| 1 | Findings meet the threshold (actionable per your review) |
| 2 | Invalid input, rejected file, `--strict` violation, or usage error |

## JSON output

Default `--format json` stdout is exactly
`{schema_version, finding_count, findings}` with deterministic ordering —
safe to pipe. `--verbose` adds `files` and per-finding `detail` (graph
paths with provenance). Diagnostics never go to stdout in JSON mode.

## CI example

```yaml
- run: aegisbench scan ./configs --strict --format json
```

Fail the build on exit code 1 (findings) or 2 (invalid/unsupported).
See `.github/workflows/ci.yml` and `docs/limitations.md` before gating
deployments on results.
