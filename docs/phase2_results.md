# Phase 2 Results (held-out + real-schema validation)

## Commands and environment

```powershell
python -m pytest                                    # 69 passed, 1 skipped
ruff check src tests benchmark                      # All checks passed
ruff format --check src tests benchmark             # clean
python -m aegisbench.benchmark                      # dev set regression
python -m aegisbench.heldout                        # this report (stdout JSON)
```

Python 3.12.0, Windows, `pip install -e .` (typer, pydantic).
No git repository exists in this workspace, so the analyzer freeze is
recorded as SHA-256 content hashes (below), not a commit revision.

## Versions

- Dev dataset: `benchmark` v1.0 (64 labeled / 8 excluded — unchanged).
- Held-out dataset: `heldout_v1` (52 labeled / 8 excluded).
- Baseline: BROAD-CMD-001 v1 (Phase 0, unchanged).
- Graph: GRAPH-CHAIN-001 v1 (MAX_DEPTH 6, 2–5 tools for multi-step).
- Adapter: mcp-adapter v1.

Analyzer freeze (SHA-256):

| File | Hash |
| --- | --- |
| `src/aegisbench/adapters/mcp.py` | `193dafe06de56285cc120daf6cb0850200ea5793876c18ea91aded83857e8994` |
| `src/aegisbench/analyzers/graph.py` | `8ea1931ef81e8a438f69ab71d3eedfac3bc0ea019d2afa5e00e8798600c3d380` |
| `src/aegisbench/heldout.py` | `66bfbac98e1db88a4a3d350f6d58bdf654f24d22e4447e43709c1084b89b97e9` |
| `src/aegisbench/metrics.py` | `30c1ecce4f977c3b87f4147039707a17c8072d5fb93f6ca258765009f3162690` |
| `src/aegisbench/models.py` | `d0d86c3349da9849ec90f35adab17200d2dae4d4bb7654377edcf5d2352fe496` |
| `src/aegisbench/parser.py` | `7d81e0e94bca3a059d103399d01882801ede47a9a698bb0f1983a10142161ed5` |
| `src/aegisbench/rules/broad_permissions.py` | `361a4494c3bdc6e0caa77cd58760aa382335a9c2175f800fb90c00f93995f784` |

Prediction hash: `0302451fae0ac3ed67aa80564ea8fb79ecb19ec23df3e43d505390eb2c8fe5ff`
(predictions frozen by label-blind code before scoring; see protocol).

## Inclusion / exclusion (held-out)

Included 52/52 labeled (all parsed). Excluded 8 (robustness only):
malformed, missing version, unknown field, wrong type, duplicate tools,
duplicate destinations, undefined refs, top-level array — all rejected
safely or parsed with warnings, none scored. Labeled-but-unparseable: 0.

## Preregistered definitions

See `docs/phase2_protocol.md` (frozen before held-out generation; no
amendments). Unit = one fixture. Positive = ≥ 1 finding of the
comparison's path class (A: any BROAD-CMD-001; B: exactly-2-edge graph
path; C: 3–6-edge graph path). Metrics per `metrics.py`; zero denominators
→ `None`. Primary: recall + FPR. Support thresholds: SUPPORTED iff
recall ≥ 0.80 and FPR ≤ 0.10; FAILURE iff recall < 0.50 or FPR > 0.25.

## Confusion matrices and metrics (held-out, measured)

| Comparison | TP | FP | TN | FN | P | R | F1 | FPR | R 95 % CI | FPR 95 % CI | Verdict |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A baseline_narrow (n=52, support 7) | 7 | 0 | 45 | 0 | 1.0 | 1.0 | 1.0 | 0.0 | [0.65, 1.0] | [0.0, 0.08] | PASS |
| B graph_direct (support 9) | 9 | 0 | 43 | 0 | 1.0 | 1.0 | 1.0 | 0.0 | [0.70, 1.0] | [0.0, 0.08] | SUPPORTED |
| C graph_chain (support 18) | 18 | 0 | 34 | 0 | 1.0 | 1.0 | 1.0 | 0.0 | [0.82, 1.0] | [0.0, 0.10] | SUPPORTED |

Per family (TP/FP/TN/FN): B — direct 6/0/0/0, fn 1/0/7/0, amb 1/0/3/0,
mix 1/0/3/0, fp 0/0/11/0, benign 0/0/8/0, partial 0/0/4/0, chain 0/0/7/0.
C — chain 7/0/0/0, fn 7/0/1/0, amb 2/0/2/0, mix 2/0/2/0, fp/benign/partial/
direct all TN with 0 FP. A — wildcard carriers exact (7/7), no FP anywhere.

## False positives / negatives

None on the held-out set for any comparison (all FP/FN lists empty).
This is reported as measured, not as an objective met — the set was
author-generated against documented semantics, so zero errors is weak
evidence (see threats). The most adversarial near-misses correctly
negative: `ho_fp_01` (scary text, no caps), `ho_fp_02/03` (near-miss/case
IDs), `ho_fp_04` + `ho_amb_01` (reversed invokes), `ho_fp_05`/`ho_mix_03`
(lone `*`, graph correctly quiet), `ho_fp_06` (legacy fields),
`ho_amb_04` (benign text hiding a true path — correctly positive).

## Unsupported-format and parser robustness

Held-out robustness 8/8 handled: 5 schema/JSON rejections, 3 parsed with
warnings and excluded (duplicates, undefined refs). Real-schema adapter:
3/3 MCP fixtures adapted; `env` secret never appears in fixture dumps;
remote `url` marked unsupported with zero invented permissions;
provenance recorded per field (5/9/1 fields); graph findings 0/0/0 as
honestly expected (no data-flow semantics declared); baseline findings 0.
No execution, no network, no real credentials at any point.

## Runtime (descriptive, environment-dependent)

Held-out 52 fixtures: baseline ~0.0004 s, graph ~0.004 s. Not a claim;
excluded from determinism tests.

## Provenance, independence, leakage

Labels: same author as the analyzer; LLM-assisted drafts; no second
reviewer — NOT independent ground truth. Leakage acknowledged: case
authors knew the documented path semantics, so labels and analyzer share
a definition (same circularity as Phase 1, mitigated but not removed by
adversarial variety). CIs above quantify sampling noise only. No protocol
amendments were made after viewing results.

## Threats and unresolved assumptions

- Invoke-direction-as-data-flow remains an assumption (`ho_amb_01` vs
  `ho_amb_02` bakes it in; a real schema may not support it).
- Small n (B support 9; CIs wide, e.g. B recall [0.70, 1.0]).
- Adversarial enrichment ≠ realistic distribution; FPR 0.0 here does not
  predict operational false-positive rates.
- Single real format (MCP file config); remote/URL and permission-gated
  tool semantics unverified beyond docs.

## Hypothesis verdicts

- B (direct paths the narrow rule misses): SUPPORTED on held-out
  (recall 1.0, FPR 0.0) — weak strength (non-independent set).
- C (multi-step chains): SUPPORTED on held-out — same caveat.
- No evidence for attack prevention, exploitability proof, general
  outperformance, or novelty. Those claims are explicitly NOT made.
