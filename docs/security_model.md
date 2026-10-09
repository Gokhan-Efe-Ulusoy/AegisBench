# Security model

## What AegisBench checks

1. **Overly broad command permissions** (`BROAD-CMD-001`): an entry in
   `tools[].permissions.commands[]` that strips to exactly `"*"`.
2. **Modeled capability paths** (`GRAPH-CHAIN-001`): a directed path
   `sensitive_source -> tool -> (tool)* -> external_destination` built
   ONLY from exact `reads` / `invokes` / `sends_to` IDs (max 6 edges).
3. **MCP file hygiene**: unknown/unsupported keys, redacted secrets,
   contradictory entries — reported as warnings, never as findings.

## What it does NOT do (guarantees)

- Never executes commands, launches servers/agents, imports scanned
  modules, contacts configured URLs, or sends data anywhere.
- Never reads outside the explicit scan root (symlink escapes skipped).
- Never auto-discovers personal configs; never reads environment secrets
  (`env`/`headers` values are redacted at the adapter and absent from all
  output — covered by regression tests).
- Never expands `${...}` variables, resolves inputs, or opens referenced
  files (`envFile`, command paths).
- No remediation, no destructive actions, no telemetry, no network use
  (the package has no network dependencies).

## Trust boundaries

- Configuration strings and descriptions are UNTRUSTED data: parsed,
  never interpreted as behavior.
- Findings are static risk indicators. Severity = hypothetical impact if
  enforced literally; confidence = certainty of the static match.
- Sandbox rules, trust prompts, approvals, and runtime permissions are
  out of scope and not evaluated.

## Diagnostic-echo caveat (documented)

Error and rejection messages may quote fields from the file being
scanned (for example, a schema-validation error names the offending
location and may include the rejected value). Diagnostics never include
content from any other file, environment variables, or secrets stores —
adapter errors structurally cannot contain `env`/`headers` values
(regression-tested). Still, treat terminal output as sensitive when the
scanned file is: review before pasting it anywhere.
