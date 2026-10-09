# AegisBench

AegisBench is a small, local-first static analyzer for AI-agent tool
permissions and MCP configuration files. Point it at a config file or
directory and it reports explicitly modeled risks — overly broad command
permissions and sensitive-source-to-external-destination capability paths —
with file paths, rule IDs, evidence, and plain-language limits. It never
executes, launches, or contacts anything it reads.

```powershell
pip install -e .
aegisbench scan ./configs --strict
aegisbench scan ./mcp.json --format json
```

A finding is a static risk indicator, not proof of exploitability. All
benchmark scores are self-consistency checks on author-generated synthetic
data — never independent evidence of real-world effectiveness. Read
`docs/limitations.md` before acting on results.

## What it does

- `scan PATH` — baseline (`BROAD-CMD-001`) + graph (`GRAPH-CHAIN-001`)
  checks over native fixtures (schema 1.0/1.1) and supported MCP configs
  (`mcpServers`/`servers`); per-file scanned/partial/skipped/rejected
  status on stderr; exits 0/1/2.
- `validate PATH` — syntax + normalization check only, never a verdict.
- `rules` / `version` — rule catalog and component versions.
- `--strict` fails on validation problems or unsupported constructs;
  `--verbose` adds full evidence paths and provenance.
- Default JSON stdout is a stable `{schema_version, finding_count,
  findings}` document, safe to pipe. See `docs/usage.md`.

## What it does NOT do

- Never executes commands, launches MCP servers/agents, imports scanned
  modules, contacts URLs, transmits data, or uses telemetry/network.
- Never reads outside the scan root, auto-discovers personal configs, or
  copies environment secrets (`env`/`headers` values are redacted).
- Never treats descriptions, filenames, or command strings as behavior.
- No MCP protocol analysis, sandbox evaluation, remediation, or
  exploitability claims. Details: `docs/security_model.md`,
  `docs/mcp_support_matrix.md`, `docs/limitations.md`.

## Exit codes

| Code | Meaning |
| ---- | ------- |
| 0 | Completed; no findings met `--fail-on` (default `medium`) |
| 1 | Findings meet the threshold (review them) |
| 2 | Invalid input, rejected file, `--strict` violation, usage error |

Limits: max file size 1 MiB; only `.json` scanned; recursive with
symlink-escape protection.

## Example text output

```text
Findings: 1

[high/high] BROAD-CMD-001: Overly broad command permission ('*' allowlist entry)
  file: agent.json
  evidence: tools[0].permissions.commands[1] = '*' (tool: shell)
  explanation: Tool allows any command via an explicit '*' entry ...
  limitations: Static indicator only, not a confirmed vulnerability ...
```

## Current rule scope

- `BROAD-CMD-001` (severity high / confidence high): matches ONLY an
  entry stripping to exactly `"*"` in `tools[].permissions.commands[]`.
  Out of scope: `ls *`, `sudo:*`, `shell:*`, `all`.
- `GRAPH-CHAIN-001` (severity high / confidence medium): matches ONLY
  explicit `sensitive_source -> tool -> external_destination` paths via
  exact `reads`/`invokes`/`sends_to` IDs (≤ 6 edges). No file/network
  access is inferred from command strings.

## Research hypothesis (unproven)

> "Modeling relationships between tools, permissions, data sources, and
> destinations may identify certain risky capability chains that isolated
> rule-based checks miss."

Hypothesis, not result. No novelty, superiority, or measured
effectiveness claimed. See `docs/scope.md`, `docs/phase2_protocol.md`,
and `docs/phase2_results.md`.

## Development

```powershell
pip install -e .
pip install pytest ruff
python -m pytest
ruff check src tests benchmark examples
ruff format --check src tests benchmark examples
```

## First run (tested walkthrough)

```powershell
aegisbench version
aegisbench scan tests/fixtures/safe --format text      # exit 0: no findings
aegisbench scan tests/fixtures/risky --format text     # exit 1: 1 BROAD-CMD-001 finding
aegisbench scan examples/mcp/01_minimal_stdio.json     # exit 0: adapted MCP, no findings
aegisbench validate examples/mcp                       # exit 2: lists one malformed demo file
aegisbench scan benchmark/dataset/direct_exfil_01.json --format text --verbose  # exit 1: graph path
```

Safe output is `No findings. No risky patterns matched.` Risky JSON output
is the stable `{schema_version, finding_count, findings}` document shown
above. Everything runs locally: AegisBench reads only the path you give
it, parses JSON statically, and writes findings to your terminal. It
starts no processes, opens no sockets, sends nothing anywhere, and reads
no files outside the scan root (see `docs/security_model.md` for the
exact guarantee and its documented diagnostic-echo caveat).

Benchmarks: `python -m aegisbench.benchmark` (dev, 64+8),
`python -m aegisbench.heldout` (held-out, 52+8). Local MCP examples:
`aegisbench scan examples/mcp` (includes one intentionally malformed file).
Docs: `docs/installation.md`, `docs/usage.md`, `CONTRIBUTING.md`.

## Reporting bugs and false positives

Open an issue with: the AegisBench version (`aegisbench version`), the
exact command, a minimal sanitized config reproducing the result (redact
secrets first — findings quote field values), expected vs actual output,
and rule ID if any. For suspected security problems in the tool itself,
describe impact without posting credentials or private paths. No
independent audit has occurred; reports are triaged as research-prototype
feedback.

All fixture strings are treated as untrusted data, never instructions.
