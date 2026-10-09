# Independent Evaluation Kit (for a second reviewer)

You are asked to produce an independent fixture set that challenges
AegisBench. Do not read `benchmark/heldout_v1/` or `docs/phase2_results.md`
before authoring: knowing current cases or scores would destroy
independence. Work only from this kit plus `docs/phase2_protocol.md`
(frozen) and `docs/acceptance_policy.md`.

## 1. Frozen operational definition (do not reinterpret)

A fixture is positive for the graph task IFF it explicitly models a
directed path `sensitive_source -> tool -> (tool)* -> external_destination`
using exact ID references. A static path is a modeled potential flow, NOT
proof of exploitability. Your labels must follow this definition even
where it conflicts with intuition (e.g. scary text with no path = safe).

## 2. Graph node and edge semantics (frozen analyzer behavior)

- Nodes: `tool` (a named tool), `permission` (a declared capability block),
  `source` (a declared data source), `destination` (a declared sink).
  Every node is an explicit fixture fact.
- Edges (all explicit, all validated against declarations):
  - `has_permission`: tool → its permission block (structural only).
  - `can_read`: source → tool, IFF the tool's `reads` lists that source ID.
  - `can_invoke`: tool → tool, IFF the invoker's `invokes` lists the
    invokee's exact name. Direction counts: invoker → invokee is the modeled
    data-flow direction.
  - `can_send_to`: tool → destination, IFF the tool's `sends_to` lists it.
- A finding needs an unbroken chain: sensitive source → … → external
  destination, at most 6 edges, no repeated nodes. Descriptions, command
  strings, legacy `file_access`/`network_access` fields, and tool names
  NEVER create edges. Missing references create no edge (with warning).
  Duplicate IDs resolve first-wins (with warning) — avoid authoring
  duplicates except as deliberate ambiguity cases (see §4).

## 3. Inclusion, exclusion, ambiguity rules

- Include: valid JSON, schema `1.0`/`1.1`, ≤ 1 MiB, labels assigned.
- Exclude from detection metrics (robustness only): unparseable files,
  schema violations, unsupported constructs, unlabeled files.
- Ambiguity cases (duplicates, dangling references, misleading text) ARE
  scored, but you MUST set `ambiguity: true` and explain which resolution
  your label assumes. Unresolvable disagreements exclude the case.

## 4. Fixture-authoring guide

- Use a fresh ID namespace (never reuse `synthetic_*` or `heldout_*`).
- Cover: realistic benign configs, direct single-tool paths, multi-step
  invoke chains (2–4 tools), broken variants (each link type removed once),
  near-miss identifiers (typo/case/plural), misleading descriptions in
  BOTH directions, reversed invocations, disconnected components, cycles,
  multiple coexisting paths, minimal/partial declarations, and broad `*`
  permissions with and without structural paths.
- Design cases to expose false negatives AND false positives.
- Keep each fixture small (≤ 6 tools) and inert (no real systems,
  credentials, or personal data).

## 5. Labeling template (one entry per fixture file)

```json
{
  "<file>.json": {
    "family": "<your scenario family>",
    "expected_chain": "risky | safe",
    "expected_direct": false,
    "expected_chain_multi": false,
    "expected_wildcard": false,
    "rationale": "why, citing exact IDs and the §2 semantics",
    "ambiguity": false
  }
}
```

`expected_chain` must equal direct OR multi. `expected_wildcard` is true
iff any `commands` entry strips to exactly `"*"`.

## 6. Keeping labels separate

Write fixtures first, then labels in a separate `labels.json`
(`{"dataset_version": "<name>", "fixtures": {...}}`). Never embed
expected results in fixture files (the schema rejects unknown fields
anyway). Exchange fixtures and labels as separate files.

## 7. Adjudication

- Two reviewers label blindly; collect disagreements per fixture.
- Adjudicate by re-reading §1–§2 only — intuition loses to the definition.
- Record each disagreement, its resolution, and the rule cited.
- Cases with no agreed label are excluded and listed with reasons.
- A case both reviewers got "wrong" versus the analyzer is still scored
  as labeled; analyst surprise is not a relabeling criterion.

## 8. Protocol freeze rule

`docs/phase2_protocol.md` and `docs/acceptance_policy.md` are frozen.
After viewing analyzer predictions you may not change labels, thresholds,
or semantics on the same set. Needed changes go in a dated amendment with
both original and amended analyses, or a new dataset version.
