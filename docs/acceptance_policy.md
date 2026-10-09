# Acceptance Policy (provisional decision criteria, frozen)

These thresholds decide what happens next — they are NOT universal
security standards and must not be quoted as such.

## Point thresholds (comparisons B and C, per `docs/phase2_protocol.md`)

- SUPPORTED: recall ≥ 0.80 AND FPR ≤ 0.10.
- FAILURE: recall < 0.50 OR FPR > 0.25.
- Otherwise INCONCLUSIVE.
- Comparison A (baseline regression): PASS iff precision and recall ≥ 0.95.

## Additional requirements (all must hold for SUPPORTED)

1. Minimum evidence: ≥ 15 expected positives AND ≥ 15 expected negatives
   per comparison. Fewer → INCONCLUSIVE regardless of point estimates.
2. Multiple independently authored scenario families on both sides
   (no single-template set counts).
3. No unresolved critical label disagreement (see kit §7); all exclusions
   listed with reasons.
4. Wilson 95 % intervals reported for recall and FPR. If the interval for
   recall extends below 0.80 or for FPR above 0.10 on a small set, report
   INCONCLUSIVE even when point estimates pass.
5. No aggregate-only claims: if any scenario family with ≥ 5 examples
   scores recall < 0.50 or FPR > 0.25, the overall verdict is at most
   INCONCLUSIVE, with the failing family named.

## Consequences

- SUPPORTED: may proceed to a second real-schema adapter study; still no
  effectiveness, novelty, or release claims.
- INCONCLUSIVE: revise the set (larger, more families) and re-evaluate
  once with a new dataset version.
- FAILURE: stop the graph direction or redesign semantics as a new
  analyzer version with a new held-out set — never retune on the same set.
