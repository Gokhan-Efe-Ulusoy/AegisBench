# Reproducibility Manifest (Phase 5 freeze)

This manifest is a recorded fingerprint of the current artifact. It is NOT
a Git commit, tag, immutable release, or external timestamp (no Git
repository exists in this workspace). It lets a reviewer verify that the
files they received match the files that produced the reported results.

## How to verify

```powershell
python -m aegisbench.freeze > freeze_actual.json
```

Compare `freeze_actual.json` against the hashes below. Every file under
`files` must match byte-for-byte except this manifest itself
(`docs/reproducibility_manifest.md`), which is excluded from hashing
because it embeds the hashes (hashing it would be circular). Any other
mismatch means the artifact changed and prior results do not transfer.
`missing` must be `[]`.

## Environment (measured)

- Python 3.12.0, Windows (primary test platform; CI targets Ubuntu).
- typer 0.27.3, pydantic 2.13.4 (dev) / 2.14.0 (clean-install check),
  pytest 9.1.1, ruff 0.16.6. Clean isolated venv install verified
  separately (see report).

## Commands producing current results (measured)

```powershell
python -m pytest                                    # 149 passed, 3 skipped
ruff check src tests benchmark examples             # All checks passed
ruff format --check src tests benchmark examples    # clean
python -m aegisbench.benchmark                      # dev: 64 incl / 8 excl
python -m aegisbench.heldout                        # heldout: 52 incl / 8 excl
python -m aegisbench.freeze                         # 205 files, 0 missing
aegisbench scan tests/fixtures/safe --format text   # exit 0
aegisbench scan tests/fixtures/risky --format json  # exit 1, 1 finding
```

Dev benchmark scores: baseline_narrow P/R/F1 1.0; baseline_on_chain
P 0.429 / R 0.273 / F1 0.333; graph_on_chain P/R/F1 1.0.
Held-out verdicts: A PASS, B SUPPORTED, C SUPPORTED (see
`docs/phase2_results.md`). Held-out prediction hash re-verified:
`0302451fae0ac3ed67aa80564ea8fb79ecb19ec23df3e43d505390eb2c8fe5ff`.

## Key hashes (full set: 205 files via `python -m aegisbench.freeze`)

The set covers source, tests (`tests/test_*.py` added in the Phase 5.1
audit — previously only fixtures were tracked), generators, benchmark
assets, examples, CI configuration, documentation, license, and project
configuration. Caches, virtual environments, and build artifacts are
intentionally excluded (see `.gitignore`).

Detection semantics (unchanged since Phase 2 — byte-identical):

- `src/aegisbench/rules/broad_permissions.py`: `361a4494c3bdc6e0caa77cd58760aa382335a9c2175f800fb90c00f93995f784`
- `src/aegisbench/models.py`: `d0d86c3349da9849ec90f35adab17200d2dae4d4bb7654377edcf5d2352fe496`
- `src/aegisbench/parser.py`: `7d81e0e94bca3a059d103399d01882801ede47a9a698bb0f1983a10142161ed5`
- `src/aegisbench/metrics.py`: `30c1ecce4f977c3b87f4147039707a17c8072d5fb93f6ca258765009f3162690`
- `src/aegisbench/heldout.py`: `b521132bd559aad8e070ab11368d1c996ac14da29e3efeea7b1da581a86a826d`
- `docs/phase2_protocol.md`: `97d16bf295ed3775b57ee511cb0c54bad48b79ea1cc71e2686d9a5961cb741de`

Hardened/extended in Phases 4–5 (no detection-semantics change; verified
by unchanged benchmark scores and regression tests):

- `src/aegisbench/analyzers/graph.py`: `b7e0ca77a8fd0bbab14cdf304e79e6abaa149a4733602884912c8e9912b15776` (additive `check_detailed`; `check()` outputs identical)
- `src/aegisbench/adapters/mcp.py`: `d84c10b5f25f4b3bcae5aac0d850c930b7ff879cee2b73a40a45381b0d5ace84` (`mcp-adapter v2`)
- `src/aegisbench/reporter.py`: `b0e3688ab02a24158e6521c1e6ede1c939d434c6d2ef2bd923bc708c15fcdd8e` (terminal-control sanitization; JSON bytes unchanged)
- `src/aegisbench/cli.py`: `01a8514226515fbd229a28f945c982fa2043908fabb4607dbde5c74938755d44`
- `src/aegisbench/evidence.py`: `08c8e17a0b93c3e8338367c68ba122b7bb8bc67abfc935a0c91e1a1b74ee47a`
- `src/aegisbench/pipeline.py`: `3ad3cbe54c2442396cf98ac5e08f89551c25ad7a7fab2c5db10155c20febe3ba`
- `src/aegisbench/blind.py`: `fad34bab9b98fc6f0b7a0d21c317a83e00918fd639d8060ff5c5d65ce9caaa94`
- `src/aegisbench/freeze.py`: covered by full-set comparison
- `src/aegisbench/benchmark.py`: `d635c35b22c806c6ee4ebb998175bb59270902f83ec5b38696aec357d0e30c38`
- `LICENSE`: `e4f996da757f33ebc6631798e03cc8cd88133b0c5954e3f1abee3eb91ed4625a` (MIT, matching pyproject declaration)
- `.gitignore`: `3539adfdde907d7e3b3b8b1ba4d22890d0729541ff5b17857df1b45cc260e8d9`
- `.github/workflows/ci.yml`: `343d45a4fea305d5a04e2a194863c7c5abb9e2e73d02a0f019718f86751acb2c`
- `docs/security_model.md`: `d3248066f1e25cf5dc51de25ea65c23a854d57ee8d95dac14eac11d145d94737`

## Provenance identification (explicit)

- Phase 1 dev dataset (72 fixtures): author-generated, deterministic
  generator, single-author review.
- Phase 2 held-out set (60 fixtures): author-generated, NOT independently
  validated; LLM-assisted drafting. Not blind, not ground truth.
- MCP fixtures and `examples/mcp/` corpus: faithful minimal
  reconstructions from official docs with synthetic values, or labeled
  synthetic; no user data, no secrets.
- No independent reviewer, no external validation, no audit, no release.
