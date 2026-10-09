# Research Scope (Phase 0 + Phase 1)

## Research hypothesis (unproven)

"Modeling relationships between tools, permissions, data sources, and
destinations may identify certain risky capability chains that isolated
rule-based checks miss."

No novelty, superiority, or real-world effectiveness is claimed. Phase 1
tests the hypothesis on a small synthetic dataset only.

## Operational definition: risky capability chain

A fixture is labeled `risky` IFF it explicitly models a directed path:

`sensitive_source -> tool -> (tool)* -> external_destination`

via exact `reads` / `invokes` / `sends_to` IDs (fixture schema v1.1).
A static path is a modeled potential flow, NOT proof of exfiltration or
exploitability. Enforcement, sandboxing, auth, and runtime data handling
are unmodeled. Severity (`high`) reflects hypothetical impact;
confidence (`medium` for graph, `high` for the syntactic baseline)
reflects match certainty, not exploit proof.

## Dataset construction and labeling (v1.0)

- 72 files in `benchmark/dataset/`: 64 labeled, 8 robustness (excluded).
- Families: `wildcard_only` 8, `narrow_safe` 8, `sensitive_read_only` 8,
  `direct_exfil` 10 (risky), `chain_exfil` 12 (risky), `broken_chain` 10,
  `benign_resemblance` 8. Risky total 22, safe 42.
- Labels in `benchmark/labels.json`, separate from analyzer code, with
  `family`, `expected_chain`, `expected_wildcard`, `rationale`, `property`.
- Key assumptions: exact ID match only (typos create no edge); invoke
  direction = data-flow direction; `commands`/`file_access`/
  `network_access`/descriptions never create graph edges; duplicate IDs
  resolve first-wins with warning; paths bounded at 6 edges.
- Generator: `python benchmark/generate.py` (deterministic, inert
  `synthetic_*` IDs, no real systems or credentials).
- See `benchmark/README.md` for per-family rationale.

## Baseline limitations (BROAD-CMD-001, Phase 0, unchanged)

Reads ONLY `tools[].permissions.commands[]`; fires IFF an entry strips to
exactly `"*"`. Intended task: narrow wildcard detection (perfect on this
dataset: TP 14, TN 50, P/R/F1 1.0). It is NOT a chain detector: applied to
the chain task it scores TP 6, FP 8, TN 34, FN 16 (P 0.429, R 0.273,
F1 0.333, FPR 0.190). The 8 FPs are `wildcard_only_*` (wildcard without a
chain path); the 16 FNs are non-wildcard `direct/chain_exfil`. Low recall
here is expected coverage difference, not a defect.

## Evaluation methodology

- Runner: `python -m aegisbench.benchmark` prints deterministic JSON
  (all fields except `elapsed_seconds`).
- Positive = >= 1 finding for the evaluated rule in that fixture.
- Three predetermined comparisons: `baseline_narrow` (vs
  `expected_wildcard`), `baseline_on_chain` (vs `expected_chain`),
  `graph_on_chain` (vs `expected_chain`).
- Metrics: TP/FP/TN/FN, precision, recall, F1, FPR; `None` for zero
  denominators (never silently 0). Malformed/ambiguous inputs go to
  `robustness_report` (8 files: parse rejections, duplicate-ID warnings,
  undefined-ref negatives), never into metrics.
- Report carries dataset/analyzer versions, per-family breakdowns, FP/FN
  examples, metric definitions, limitations. Runtime is measured but
  excluded from determinism tests.

## Results (measured, dataset v1.0)

- `baseline_narrow` overall: TP 14, FP 0, TN 50, FN 0; P/R/F1 1.0, FPR 0.0.
- `baseline_on_chain` overall: TP 6, FP 8, TN 34, FN 16; P 0.429, R 0.273,
  F1 0.333, FPR 0.190. Per family: `direct_exfil` R 0.30 (3/10),
  `chain_exfil` R 0.25 (3/12), `wildcard_only` FPR 1.0 (8/8, task mismatch).
- `graph_on_chain` overall: TP 22, FP 0, TN 42, FN 0; P/R/F1 1.0, FPR 0.0.
  Per family: `direct_exfil` 10/10, `chain_exfil` 12/12, all safe families
  TN with FPR 0.0. No FP/FN examples exist on this dataset.
- Runtime (illustrative, machine-dependent): baseline ~0.0004 s,
  graph ~0.004 s for 64 fixtures.
- Failure cases for baseline-as-chain-detector: FN `direct_exfil_01`,
  `chain_exfil_01/02/03/...` (chains without `*`); FP `wildcard_only_01..08`
  (wildcard without chain). These are coverage differences per the
  predefined tasks, listed explicitly in the report.

## Threats to validity

- Graph's perfect score is circular by construction: labels and analyzer
  share the same explicit-path definition on a tiny synthetic set. It does
  NOT demonstrate real-world effectiveness or superiority.
- Synthetic IDs and templates; no real agent formats, no adversarial or
  blind labeling, single-author review.
- Small n (22 risky); confidence intervals wide; per-family `None` metrics
  where support is 0.
- Invoke-as-data-flow is an assumption, not an established semantic.
- Parser/analyzer versions and pydantic messages pinned only loosely.

## What stronger evidence would require

- Larger, independently labeled, adversarially reviewed dataset with
  held-out fixtures the analyzer author never saw.
- Verified adapters for real agent schemas (not synthetic) plus adapter tests.
- Pre-registered evaluation, blind scoring, and reported confidence
  intervals rather than point scores on n=64.
- Negative controls showing no FP inflation on realistic benign configs.
- Replication on a second implementation of the path semantics.
- Until then: no release, no publication, no external validation claims.

## Phase 2 status (held-out + MCP adapter)

- Protocol frozen before held-out generation: `docs/phase2_protocol.md`
  (no amendments). Full measured results: `docs/phase2_results.md`.
- Held-out `heldout_v1` (52 labeled / 8 excluded, author-generated, not
  independent): A baseline_narrow PASS; B graph_direct SUPPORTED
  (TP 9, TN 43, recall 1.0 [0.70, 1.0], FPR 0.0); C graph_chain SUPPORTED
  (TP 18, TN 34, recall 1.0 [0.82, 1.0], FPR 0.0). Zero FP/FN is weak
  evidence given same-author labels; CIs do not fix construction bias.
- MCP client file config verified against official docs and adapted
  narrowly (`mcp-adapter v1`, provenance per field, `env` redacted,
  remote-URL entries unsupported, no invented edges, no execution).
- Unsupported claims remain unsupported: no attack prevention,
  exploitability proof, general outperformance, or novelty is claimed.
