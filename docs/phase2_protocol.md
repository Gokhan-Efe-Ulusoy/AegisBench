# Phase 2 Evaluation Protocol (frozen before held-out results)

Status: FROZEN. Do not change after viewing held-out results without a
dated amendment appendix reporting both original and amended analyses.

## Research question

Does explicit graph-based analysis identify modeled
sensitive-data-to-external-destination paths that a narrow permission rule
misses, while maintaining acceptable precision on realistic benign and
adversarial near-miss configurations? (Hypothesis, unproven.)

## Comparisons (separate tasks — raw scores are NOT comparable)

### A. `baseline_narrow`

- Analyzer: BROAD-CMD-001, unchanged (reads only
  `tools[i].permissions.commands[j]`, fires iff stripped entry == `"*"`).
- Label: `expected_wildcard` (true iff any commands entry strips to `"*"`).
- Purpose: regression check that the baseline still does its declared task.
  Its score says NOTHING about chain detection.

### B. `graph_direct_exfil`

- Analyzer: GRAPH-CHAIN-001 paths with EXACTLY 2 edges
  (`source --can_read--> tool --can_send_to--> destination`).
- Positive case = one tool explicitly lists the sensitive source in
  `reads` AND an external destination in `sends_to`.
- Label: `expected_direct` (true iff such a single-tool pair is modeled).

### C. `graph_chain_exfil`

- Analyzer: GRAPH-CHAIN-001 paths with 3–6 edges
  (`source --can_read--> tool (--can_invoke--> tool)+ --can_send_to--> dest`,
  i.e. 2–5 tools; MAX_DEPTH = 6 edges, cycle-safe, deterministic).
- Directionality: invoker → invokee is treated as the data-flow direction
  (documented assumption, not established fact).
- Label: `expected_chain_multi` (true iff such a multi-tool path is modeled).

## Preregistered definitions (all comparisons)

- Unit of analysis: one fixture file.
- Predictor positive: ≥ 1 finding of the comparison's path class in that
  fixture (evaluated via `find_paths`, classified by edge count; the
  analyzer itself is NOT modified to expose this).
- TP: label risky + predicted. FP: label safe + predicted.
  TN: label safe + not predicted. FN: label risky + not predicted.
- precision = TP/(TP+FP); recall = TP/(TP+FN);
  F1 = 2PR/(P+R); FPR = FP/(FP+TN). Zero denominators → `None` (never 0).
- Primary metrics: recall (catches modeled paths?) and FPR (stays quiet
  on benign?). Secondary: precision, F1, support counts.
- Inclusion: labeled held-out fixture that parses under schema 1.0/1.1,
  ≤ 1 MiB, `.json`. Exclusion (robustness report only, never in metrics):
  parse/schema failures, unsupported constructs, unlabeled files.
- Duplicates/dangling references: INCLUDED in primary metrics with labels
  assigned per documented resolution semantics (duplicate IDs: first wins
  with warning; dangling `reads`/`sends_to`/`invokes`: no edge + warning).
  A secondary sensitivity analysis re-computes B/C excluding
  warning-bearing fixtures.
- Warnings never flip positivity; warning counts are reported.
- Confidence: Wilson 95 % intervals for recall and FPR. Intervals describe
  sampling noise only; they do NOT correct construction bias or leakage.

## Support / failure / inconclusive (per comparison B and C)

- SUPPORTED: recall ≥ 0.80 AND FPR ≤ 0.10 on included held-out fixtures.
- FAILURE: recall < 0.50 OR FPR > 0.25.
- Otherwise INCONCLUSIVE.
- For A (regression): pass iff precision and recall ≥ 0.95; else FAILURE
  (signals baseline breakage, not a research result).

## Held-out hygiene (author-generated, NOT independent)

No second reviewer is available. The set is labeled author-generated and
not independently validated; an LLM-assisted draft is not ground truth.
Procedure: (1) write generator from this protocol; (2) freeze dataset and
record SHA-256 hashes; (3) freeze analyzer sources and record hashes;
(4) run predictions and freeze prediction hashes BEFORE scoring labels;
(5) score once. No threshold/depth/semantic tuning against held-out labels
on the same set — any post-hoc change creates a new analyzer version and a
new held-out set, or is labeled exploratory.

## Real-schema adapter (Stage 3)

One verified real format, narrow adapter, provenance per normalized field,
unsupported constructs rejected or marked, no description-as-behavior, no
invoke-as-transfer unless the schema supports it, no execution/network,
no secrets. Adapter fixtures are reported separately from synthetic metrics.

## Amendment log

- (none; protocol frozen before held-out generation)
