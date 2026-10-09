# Limitations (read before acting on findings)

- **Not exploitability proof.** A finding shows a declared pattern or a
  modeled path, not that data can or will flow. Always confirm in context.
- **No independent validation.** All benchmark datasets are
  author-generated with LLM assistance (see `docs/phase2_results.md` and
  the reproducibility manifest). Perfect benchmark scores measure
  self-consistency, not real-world effectiveness.
- **MCP file configs only.** No MCP protocol analysis, no transport/auth
  review, no sandbox evaluation, no tool-behavior analysis. Adapted
  configs structurally cannot produce graph findings (no data-flow
  semantics declared) — that is a scope boundary, not a clean verdict.
- **Narrow rules.** `BROAD-CMD-001` matches only exact `"*"`;
  `GRAPH-CHAIN-001` matches only exact-ID paths up to 6 edges with the
  documented invoke-direction assumption. Everything else is invisible.
- **Small synthetic evidence.** Dozens of fixtures, one real schema, one
  author. Confidence intervals are wide; construction bias is uncorrected.
- **Local-only.** Point it only at files you intend to share in output;
  findings quote field values (never secrets — but review before pasting).

Unsupported claims: "production-grade", "complete MCP security", "zero
false positives", "prevents exfiltration", "industry-leading", novelty, or
superiority over established tools. None of these is made here.

## Platform notes

- Developed and tested on Windows (Python 3.12). Symlink-escape tests
  skip without symlink privilege and pass in CI-like environments;
  symlink escapes are still always skipped at runtime, never followed.
- Finding paths use POSIX separators on all platforms for determinism.
- Non-ASCII terminal output follows the console encoding; JSON output is
  UTF-8 as produced. Set `PYTHONIOENCODING=utf-8` if your console mangles
  characters.
- GitHub Actions CI targets Ubuntu + Python 3.12/3.13. Remote CI runs
  have not been executed from this environment and remain unverified;
  the workflow file is reviewed but not run.
