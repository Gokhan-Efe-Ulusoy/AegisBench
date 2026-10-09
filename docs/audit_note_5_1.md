# Audit Note 5.1 — Count Reconciliation (evidence, not history rewrite)

## Test-count sequence

- Phase 4 final report: 99 passed, 1 skipped.
- Phase 5 opening baseline (measured before any Phase 5 edit): 126 passed, 1 skipped.
- Phase 5 final and current: 149 passed, 3 skipped (152 collected).

Current per-file collection (measured with `pytest --collect-only -q`):
benchmark 7, blind 6, cli 8, cli_mvp 14, corpus 8, evidence 4, graph 12,
heldout 8, mcp_adapter 20, metrics 6, parser 9, pipeline 14, rules 11,
security_regressions 25. Total 152 = 149 passed + 3 skipped.

## What is explained

- 126 → 149: fully explained. The only test file added in Phase 5 is
  `tests/test_security_regressions.py` (newest mtime in `tests/`), which
  collects 25 cases (23 passed + 2 platform-dependent symlink skips on
  this machine). 126 + 23 = 149 passed; 1 + 2 = 3 skipped. The two new
  skips are the symlink-escape tests skipping without symlink privilege,
  consistent with the pre-existing documented platform behavior.
- Current tree minus that file collects exactly 127 = 126 passed +
  1 skipped, corroborating the Phase 5 opening baseline figure.

## What is NOT resolved

- 99 → 126 (+27 with no intervening file changes): UNVERIFIED. No Git
  history, command logs, or snapshots exist to reconstruct the Phase 4
  run. Candidate explanations (subset run, misread output) have no
  supporting evidence and are not asserted. The Phase 4 figure should be
  treated as unreliable; all Phase 5 figures are reproducible from the
  current tree as shown above.

## Security-test count correction

- `tests/test_security_regressions.py` contains 19 test functions, one
  parametrized ×7, collecting 25 cases (23 passed, 2 skipped here).
- The Phase 5 report's "28 cases" and "29 new tests" are both inaccurate;
  the correct citable count is 19 functions / 25 collected cases. No other
  test files were added in Phase 5 (`test_cli_mvp.py` was strengthened in
  place; its mtime reflects edits, not addition). Tests were not changed
  to match any number.

## Manifest correction (this audit)

- `tests/test_*.py` were previously untracked by the freeze (only
  fixtures were). Added `TEST_FILES` to `freeze.py`; set grew
  189 → 203 files, 0 missing. No analyzer, fixture, label, or threshold
  bytes changed in this audit.
