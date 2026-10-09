# Benchmark dataset v1.0 (synthetic, inert)

72 files in `benchmark/dataset/`: 64 labeled for primary metrics, 8
robustness files excluded from metrics. Regenerate deterministically with:

```powershell
python benchmark/generate.py
python -m aegisbench.benchmark
```

## Labeling

Labels live in `benchmark/labels.json`, separate from analyzer code.
Each entry has `family`, `expected_chain` (`risky`/`safe`),
`expected_wildcard` (bool), `rationale`, and `property` (what is tested).

- `expected_chain = risky` IFF the fixture explicitly models a directed
  path `sensitive_source -> tool -> (tool)* -> external_destination` via
  exact `reads` / `invokes` / `sends_to` IDs. Nothing is inferred from
  descriptions, `commands`, `file_access`, or `network_access`.
- `expected_wildcard = true` IFF some `permissions.commands[]` strips to
  exactly `"*"`. This is the baseline's intended narrow task.
- A static path is a modeled potential flow, NOT proof of exploitability.
  Enforcement, sandboxing, and runtime data handling are unmodeled.

## Families (labeled 64)

| Family | n | Chain | Wildcard | Purpose |
| --- | --- | --- | --- | --- |
| `wildcard_only` | 8 | safe | true | Narrow-rule TP; chain-task FP when baseline misapplied |
| `narrow_safe` | 8 | safe | false | Plain negatives |
| `sensitive_read_only` | 8 | safe | false | Read-alone must not flag |
| `direct_exfil` | 10 | risky | 3 true | Single-tool source->tool->dest |
| `chain_exfil` | 12 | risky | 3 true | 2–3 hop invoke chains; baseline misses most |
| `broken_chain` | 10 | safe | false | Missing/wrong link (no invoke, wrong source/dest, dangling ref, reversed) |
| `benign_resemblance` | 8 | safe | false | Lookalikes: `ls *`, `sudo:*`, near-miss IDs, text-only risk, legacy fields, name-only, self-loop |

Risky total: 22. Safe total: 42.

## Robustness (excluded 8)

Malformed JSON, missing version, unknown field, wrong type, duplicate
tools/sources, undefined refs, top-level array. The runner parses them to
prove safe rejection (or warning + exclusion when parsable but ambiguous)
and lists them in `robustness_report`. They never enter TP/FP/TN/FN.

## Assumptions and limits

- IDs are synthetic (`synthetic_*`); no real systems or data.
- Exact ID match only; `synthetic_hr_db_backup` does not match
  `synthetic_hr_db`.
- Invoke direction = data-flow direction (invoker can pass data to invokee).
- Small, synthetic, non-blind; graph's perfect score here is circular by
  construction (labels and analyzer share the path definition) and must
  not be read as real-world effectiveness.
