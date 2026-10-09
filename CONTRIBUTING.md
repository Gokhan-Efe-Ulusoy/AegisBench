# Contributing

## Ground rules

- Static analysis only: no execution, no network, no new runtime
  dependencies without a documented reason.
- Small, readable changes; deterministic output; tests for every feature.
- Never tune analyzer semantics against benchmark labels on the same set.
  New semantics = new analyzer version + new held-out data (or an
  explicitly exploratory label).

## Adding a rule safely

1. Read ONLY documented fixture fields; treat all strings as untrusted.
2. Emit the existing `Finding` fields unchanged (severity vs confidence
   kept separate; limitations always state non-proof).
3. Register the rule in the `rules` command catalog.
4. Add unit tests: trigger, benign counterexamples, determinism.
5. Update `docs/` scope and limitations honestly.

## Adding an adapter safely

1. Verify field semantics against authoritative docs first; record sources
   and what was NOT verifiable in `docs/mcp_support_matrix.md` style.
2. Keep parsing/normalization separate from analysis; preserve provenance
   per normalized field.
3. Redact secrets (never copy values into the fixture or output); mark
   unsupported constructs explicitly; never coerce types or guess.
4. Add valid/invalid/missing/unknown/duplicate/unsupported/provenance tests.

## Reporting issues

False positives/negatives: include the (sanitized) config, expected vs
actual result, rule ID, and AegisBench version from `aegisbench version`.
Redact secrets before sharing. Security-sensitive reports: describe impact
without posting credentials or private paths.
