# Held-out adversarial set v1 (`heldout_v1`)

52 labeled + 8 robustness fixtures in `benchmark/heldout_v1/fixtures/`.
Regenerate deterministically with:

```powershell
python benchmark/heldout_v1/generate.py
python -m aegisbench.heldout
```

## Status: author-generated, NOT independently validated

No second reviewer was available. Cases were hand-enumerated from
`docs/phase2_protocol.md` by the same author as the analyzer, with LLM
drafting assistance. This is not blind external ground truth and must not
be described as such. Hygiene actually implemented:

1. Generator frozen before any held-out scoring.
2. Analyzer sources frozen (SHA-256 recorded in `docs/phase2_results.md`).
3. Predictions written to `predictions.json` (hash recorded) by code that
   never reads `labels.json`; scoring happens in a separate step.
4. No tuning against held-out labels on this set (protocol rule).

## Families (labeled 52; risky 27 / safe 25 — adversarially enriched)

| Family | n | Direct | Multi | Purpose |
| --- | --- | --- | --- | --- |
| `ho_benign_realistic` | 8 | 0 | 0 | Plausible safe configs, incl. empty tools |
| `ho_direct_risky` | 6 | 6 | 0 | Single-tool exfiltration + noise/order variants |
| `ho_chain_risky` | 7 | 0 | 7 | 2/3/4-hop, diamond, fan-out, two-path, reversed order |
| `ho_adversarial_fp` | 11 | 0 | 0 | Scary text, near-miss/case IDs, reversed invokes, lone `*`, legacy fields, ominous names, loops, disconnected, typos, hollow relay |
| `ho_adversarial_fn` | 8 | 1 | 7 | Deep/reversed/decoy/minimal/relay/dual-path cases |
| `ho_partial` | 4 | 0 | 0 | Empty/missing permissions, unreferenced declarations |
| `ho_ambiguous_invoke` | 4 | 1 | 2 | Reverse-only (safe) vs mutual/self/direct vs misleading text (risky) |
| `ho_wildcard_mixed` | 4 | 1 | 2 | Wildcard × chain independence |

Labels in `labels.json`: `expected_chain`, `expected_direct`,
`expected_chain_multi`, `expected_wildcard`, `rationale`. Overall
`expected_chain` = direct OR multi.

## Robustness (excluded 8)

Malformed, missing version, unknown field, wrong type, duplicate tools,
duplicate destinations, undefined refs, top-level array. Reported with safe
rejection behavior; never scored.
