"""Deterministic generator for the held-out adversarial set (heldout_v1).

Run: `python benchmark/heldout_v1/generate.py` from the repo root.
Output: `benchmark/heldout_v1/fixtures/*.json` + `benchmark/heldout_v1/labels.json`.

Procedure (new, independent of benchmark/generate.py): hand-enumerated
cases below, each with family, labels, and rationale. IDs use the
``heldout_*`` namespace so overlap with the dev set is impossible.
All values are inert synthetic tokens. No fixture content is executed.

Author-generated, NOT independently validated: no second reviewer was
available. Predictions are frozen (hashed) before scoring; see
``src/aegisbench/heldout.py``. An LLM assisted drafting; that is not
ground truth. Distribution is adversarially enriched, NOT realistic.
"""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).parent
FIX_DIR = HERE / "fixtures"
DATASET_VERSION = "heldout_v1"

S1 = "heldout_patient_records"  # sensitive
S2 = "heldout_salary_table"  # sensitive
N1 = "heldout_public_faq"  # non-sensitive
N2 = "heldout_sample_logs"  # non-sensitive
E1 = "heldout_partner_api"  # external
E2 = "heldout_public_feed"  # external
I1 = "heldout_local_archive"  # internal
I2 = "heldout_team_chat"  # internal


def _doc(tools, sources=None, dests=None):
    doc: dict = {"schema_version": "1.1", "agent_name": "heldout-agent", "tools": tools}
    if sources is not None:
        doc["data_sources"] = sources
    if dests is not None:
        doc["destinations"] = dests
    return doc


def _t(name, perms=None, desc="Inert heldout tool."):
    t: dict = {"name": name, "description": desc}
    if perms is not None:
        t["permissions"] = perms
    return t


def _s(sid, sens):
    return {"id": sid, "sensitivity": sens}


def _d(did, trust):
    return {"id": did, "trust": trust}


def _label(family, direct, multi, wildcard, rationale):
    chain = direct or multi
    return {
        "family": family,
        "expected_chain": "risky" if chain else "safe",
        "expected_direct": direct,
        "expected_chain_multi": multi,
        "expected_wildcard": wildcard,
        "rationale": rationale,
    }


def build():
    F, L = {}, {}

    def add(fname, doc, family, direct, multi, wildcard, rationale):
        F[fname] = doc
        L[fname] = _label(family, direct, multi, wildcard, rationale)

    # --- realistic benign x8 (all safe) ---
    add(
        "ho_benign_01.json",
        _doc([_t("shell", {"commands": ["ls", "git status"]})]),
        "ho_benign_realistic",
        False,
        False,
        False,
        "Named commands only.",
    )
    add(
        "ho_benign_02.json",
        _doc(
            [_t("reader", {"reads": [N1]}), _t("logger", {"sends_to": [I1]})],
            [_s(N1, "non-sensitive")],
            [_d(I1, "internal")],
        ),
        "ho_benign_realistic",
        False,
        False,
        False,
        "Non-sensitive read, internal send, unlinked tools.",
    )
    add(
        "ho_benign_03.json",
        _doc([_t("reader", {"reads": [S1]})], [_s(S1, "sensitive")], None),
        "ho_benign_realistic",
        False,
        False,
        False,
        "Sensitive read with no send path.",
    )
    add(
        "ho_benign_04.json",
        _doc(
            [_t("reader", {"reads": [S1], "sends_to": [I1]})],
            [_s(S1, "sensitive")],
            [_d(I1, "internal")],
        ),
        "ho_benign_realistic",
        False,
        False,
        False,
        "Sensitive read sent internally only.",
    )
    add(
        "ho_benign_05.json",
        _doc([_t("a", {"commands": ["cat"]}), _t("b")]),
        "ho_benign_realistic",
        False,
        False,
        False,
        "Missing/empty permissions blocks.",
    )
    add(
        "ho_benign_06.json",
        _doc(
            [
                _t("viewer", {"reads": [N2], "invokes": ["printer"]}),
                _t("printer", {"sends_to": [I2]}),
            ],
            [_s(N2, "non-sensitive")],
            [_d(I2, "internal")],
        ),
        "ho_benign_realistic",
        False,
        False,
        False,
        "Complete chain shape, non-sensitive + internal.",
    )
    add(
        "ho_benign_07.json",
        _doc([_t("shell", {"commands": ["ls", "cat"]})], [], []),
        "ho_benign_realistic",
        False,
        False,
        False,
        "Empty sources/destinations.",
    )
    add(
        "ho_benign_08.json",
        _doc([]),
        "ho_benign_realistic",
        False,
        False,
        False,
        "No tools at all.",
    )

    # --- direct risky x6 ---
    add(
        "ho_direct_01.json",
        _doc(
            [_t("sender", {"reads": [S1], "sends_to": [E1]})],
            [_s(S1, "sensitive")],
            [_d(E1, "external")],
        ),
        "ho_direct_risky",
        True,
        False,
        False,
        "Canonical single-tool exfiltration.",
    )
    add(
        "ho_direct_02.json",
        _doc(
            [_t("sender", {"commands": ["*", "ls"], "reads": [S2], "sends_to": [E2]})],
            [_s(S2, "sensitive")],
            [_d(E2, "external")],
        ),
        "ho_direct_risky",
        True,
        False,
        True,
        "Direct path plus exact wildcard.",
    )
    add(
        "ho_direct_03.json",
        _doc(
            [
                _t("sender", {"reads": [S1], "sends_to": [E1]}),
                _t("n1", {"commands": ["ls"]}),
                _t("n2", {"reads": [N1]}),
            ],
            [_s(S1, "sensitive"), _s(N1, "non-sensitive")],
            [_d(E1, "external")],
        ),
        "ho_direct_risky",
        True,
        False,
        False,
        "Direct path buried among benign noise tools.",
    )
    add(
        "ho_direct_04.json",
        _doc(
            [_t("sender", {"reads": [S2], "sends_to": [E1, I1]})],
            [_s(S2, "sensitive")],
            [_d(E1, "external"), _d(I1, "internal")],
        ),
        "ho_direct_risky",
        True,
        False,
        False,
        "Sends to external AND internal; external branch counts.",
    )
    add(
        "ho_direct_05.json",
        _doc(
            [_t("mover", {"reads": [S1], "sends_to": [E2]})],
            [_s(N1, "non-sensitive"), _s(S1, "sensitive")],
            [_d(E2, "external")],
        ),
        "ho_direct_risky",
        True,
        False,
        False,
        "Second source entry is the sensitive one read.",
    )
    add(
        "ho_direct_06.json",
        _doc(
            [_t("bare", {"reads": [S1], "sends_to": [E1]})],
            [_s(S1, "sensitive")],
            [_d(E1, "external")],
        ),
        "ho_direct_risky",
        True,
        False,
        False,
        "Minimal tool: no commands, no description reliance.",
    )

    # --- multi-step risky x8 ---
    add(
        "ho_chain_01.json",
        _doc(
            [
                _t("reader", {"reads": [S1], "invokes": ["sender"]}),
                _t("sender", {"sends_to": [E1]}),
            ],
            [_s(S1, "sensitive")],
            [_d(E1, "external")],
        ),
        "ho_chain_risky",
        False,
        True,
        False,
        "Canonical 2-tool chain.",
    )
    add(
        "ho_chain_02.json",
        _doc(
            [
                _t("sender", {"sends_to": [E1]}),
                _t("reader", {"reads": [S1], "invokes": ["sender"]}),
            ],
            [_s(S1, "sensitive")],
            [_d(E1, "external")],
        ),
        "ho_chain_risky",
        False,
        True,
        False,
        "Tools listed sender-first; order must not matter.",
    )
    add(
        "ho_chain_03.json",
        _doc(
            [
                _t("reader", {"reads": [S2], "invokes": ["relay"]}),
                _t("relay", {"invokes": ["sender"]}),
                _t("sender", {"sends_to": [E2], "commands": ["*"]}),
            ],
            [_s(S2, "sensitive")],
            [_d(E2, "external")],
        ),
        "ho_chain_risky",
        False,
        True,
        True,
        "3-hop chain with wildcard on sender.",
    )
    add(
        "ho_chain_04.json",
        _doc(
            [
                _t("r", {"reads": [S1], "invokes": ["m1"]}),
                _t("m1", {"invokes": ["m2"]}),
                _t("m2", {"invokes": ["s"]}),
                _t("s", {"sends_to": [E1]}),
            ],
            [_s(S1, "sensitive")],
            [_d(E1, "external")],
        ),
        "ho_chain_risky",
        False,
        True,
        False,
        "4-hop chain within depth bound.",
    )
    add(
        "ho_chain_05.json",
        _doc(
            [
                _t("r1", {"reads": [S1], "invokes": ["s"]}),
                _t("r2", {"reads": [S2], "invokes": ["s"]}),
                _t("s", {"sends_to": [E1]}),
            ],
            [_s(S1, "sensitive"), _s(S2, "sensitive")],
            [_d(E1, "external")],
        ),
        "ho_chain_risky",
        False,
        True,
        False,
        "Diamond fan-in: two readers, one sender.",
    )
    add(
        "ho_chain_06.json",
        _doc(
            [
                _t("r", {"reads": [S1], "invokes": ["s1"]}),
                _t("s1", {"sends_to": [E1]}),
                _t("s2", {"sends_to": [I1]}),
            ],
            [_s(S1, "sensitive")],
            [_d(E1, "external"), _d(I1, "internal")],
        ),
        "ho_chain_risky",
        False,
        True,
        False,
        "Fan-out: invoked sender is external.",
    )
    add(
        "ho_chain_07.json",
        _doc(
            [
                _t("ra", {"reads": [S1], "invokes": ["sa"]}),
                _t("sa", {"sends_to": [E1]}),
                _t("rb", {"reads": [N1], "invokes": ["sb"]}),
                _t("sb", {"sends_to": [E2]}),
            ],
            [_s(S1, "sensitive"), _s(N1, "non-sensitive")],
            [_d(E1, "external"), _d(E2, "external")],
        ),
        "ho_chain_risky",
        False,
        True,
        False,
        "Two independent paths; one complete.",
    )

    # --- adversarial FP-seeking x11 (all safe) ---
    scary = "Exfiltrates all records to the partner API immediately (inert text)."
    add(
        "ho_fp_01.json",
        _doc(
            [_t("chat", {"commands": ["ls"]}, desc=scary)],
            [_s(S1, "sensitive")],
            [_d(E1, "external")],
        ),
        "ho_adversarial_fp",
        False,
        False,
        False,
        "Scary description, zero capability fields.",
    )
    add(
        "ho_fp_02.json",
        _doc(
            [_t("reader", {"reads": ["heldout_patient_record"]})],
            [_s(S1, "sensitive")],
            [_d(E1, "external")],
        ),
        "ho_adversarial_fp",
        False,
        False,
        False,
        "Near-miss singular ID matches nothing.",
    )
    add(
        "ho_fp_03.json",
        _doc(
            [_t("reader", {"reads": ["HELDOUT_PATIENT_RECORDS"]})],
            [_s(S1, "sensitive")],
            [_d(E1, "external")],
        ),
        "ho_adversarial_fp",
        False,
        False,
        False,
        "Case differs; exact match required.",
    )
    add(
        "ho_fp_04.json",
        _doc(
            [
                _t("reader", {"reads": [S1]}),
                _t("sender", {"sends_to": [E1], "invokes": ["reader"]}),
            ],
            [_s(S1, "sensitive")],
            [_d(E1, "external")],
        ),
        "ho_adversarial_fp",
        False,
        False,
        False,
        "Reversed invoke (sender->reader) carries nothing outward.",
    )
    add(
        "ho_fp_05.json",
        _doc(
            [_t("shell", {"commands": ["*"]}), _t("reader", {"reads": [S1]})],
            [_s(S1, "sensitive")],
            [_d(I1, "internal")],
        ),
        "ho_adversarial_fp",
        False,
        False,
        True,
        "Broad '*' with no external destination; graph must not FP.",
    )
    add(
        "ho_fp_06.json",
        _doc(
            [_t("legacy", {"file_access": [S1], "network_access": [E1]})],
            [_s(S1, "sensitive")],
            [_d(E1, "external")],
        ),
        "ho_adversarial_fp",
        False,
        False,
        False,
        "Legacy fields name the pair but create no edges.",
    )
    add(
        "ho_fp_07.json",
        _doc(
            [_t("exfiltrator", {"commands": ["ls"]})], [_s(S1, "sensitive")], [_d(E1, "external")]
        ),
        "ho_adversarial_fp",
        False,
        False,
        False,
        "Ominous tool name with no capabilities.",
    )
    add(
        "ho_fp_08.json",
        _doc(
            [_t("loop", {"reads": [S1], "invokes": ["loop"], "sends_to": [I1]})],
            [_s(S1, "sensitive")],
            [_d(I1, "internal"), _d(E1, "external")],
        ),
        "ho_adversarial_fp",
        False,
        False,
        False,
        "Self-loop sent internally; external dest unlinked.",
    )
    add(
        "ho_fp_09.json",
        _doc(
            [_t("reader", {"reads": [S1]}), _t("sender", {"sends_to": [E1]})],
            [_s(S1, "sensitive")],
            [_d(E1, "external")],
        ),
        "ho_adversarial_fp",
        False,
        False,
        False,
        "Disconnected components; no invoke edge.",
    )
    add(
        "ho_fp_10.json",
        _doc(
            [_t("reader", {"reads": ["heldout_typo_src"], "sends_to": [E1]})],
            [_s(S1, "sensitive")],
            [_d(E1, "external")],
        ),
        "ho_adversarial_fp",
        False,
        False,
        False,
        "Typo source reference; missing refs create no edge.",
    )

    add(
        "ho_fp_11.json",
        _doc(
            [
                _t("reader", {"reads": [S1], "invokes": ["relay"]}),
                _t("relay", {}),
                _t("sender", {"sends_to": [E1]}),
            ],
            [_s(S1, "sensitive")],
            [_d(E1, "external")],
        ),
        "ho_adversarial_fp",
        False,
        False,
        False,
        "Hollow relay (empty perms): invoke edge exists but relay sends nowhere.",
    )

    # --- adversarial FN-seeking x8 (all risky) ---
    add(
        "ho_fn_01.json",
        _doc(
            [
                _t("a", {"reads": [S2], "invokes": ["b"]}),
                _t("b", {"invokes": ["c"]}),
                _t("c", {"invokes": ["d"]}),
                _t("d", {"sends_to": [E2]}),
            ],
            [_s(S2, "sensitive")],
            [_d(E2, "external")],
        ),
        "ho_adversarial_fn",
        False,
        True,
        False,
        "Deep 4-hop chain near the depth bound.",
    )
    add(
        "ho_fn_02.json",
        _doc(
            [
                _t("s", {"sends_to": [E1]}),
                _t("m", {"invokes": ["s"]}),
                _t("r", {"reads": [S1], "invokes": ["m"]}),
            ],
            [_s(S1, "sensitive")],
            [_d(E1, "external")],
        ),
        "ho_adversarial_fn",
        False,
        True,
        False,
        "Fully reversed listing order.",
    )
    add(
        "ho_fn_03.json",
        _doc(
            [
                _t("r", {"reads": [S1], "invokes": ["s"]}),
                _t("s", {"sends_to": [E1]}),
                _t("decoy", {"reads": [S1]}),
                _t("helper", {"commands": ["ls", "*"]}),
            ],
            [_s(S1, "sensitive")],
            [_d(E1, "external")],
        ),
        "ho_adversarial_fn",
        False,
        True,
        True,
        "True chain beside decoys (incl. unrelated wildcard).",
    )
    add(
        "ho_fn_04.json",
        _doc(
            [_t(" Heldout Odd ", {"reads": [S1], "invokes": ["s"]}), _t("s", {"sends_to": [E1]})],
            [_s(S1, "sensitive")],
            [_d(E1, "external")],
        ),
        "ho_adversarial_fn",
        False,
        True,
        False,
        "Odd tool names still match exactly.",
    )
    add(
        "ho_fn_05.json",
        _doc(
            [
                _t("r", {"reads": [S1], "invokes": ["pure"]}),
                _t("pure", {"invokes": ["s"]}),
                _t("s", {"sends_to": [E2]}),
            ],
            [_s(S1, "sensitive")],
            [_d(E2, "external")],
        ),
        "ho_adversarial_fn",
        False,
        True,
        False,
        "Pure relay tool carries only invokes.",
    )
    add(
        "ho_fn_06.json",
        _doc(
            [
                _t("r", {"reads": [S1], "sends_to": [I1], "invokes": ["s"]}),
                _t("s", {"sends_to": [E1]}),
            ],
            [_s(S1, "sensitive")],
            [_d(I1, "internal"), _d(E1, "external")],
        ),
        "ho_adversarial_fn",
        False,
        True,
        False,
        "Reader also sends internally; external path remains.",
    )
    add(
        "ho_fn_07.json",
        _doc(
            [_t("only", {"reads": [S2], "sends_to": [E2]})],
            [_s(N2, "non-sensitive"), _s(S2, "sensitive")],
            [_d(I2, "internal"), _d(E2, "external")],
        ),
        "ho_adversarial_fn",
        True,
        False,
        False,
        "Direct path among distractor declarations.",
    )
    add(
        "ho_fn_08.json",
        _doc(
            [
                _t("r1", {"reads": [S1], "invokes": ["s1"]}),
                _t("s1", {"sends_to": [I1]}),
                _t("r2", {"reads": [S2], "invokes": ["s2"]}),
                _t("s2", {"sends_to": [E2]}),
            ],
            [_s(S1, "sensitive"), _s(S2, "sensitive")],
            [_d(I1, "internal"), _d(E2, "external")],
        ),
        "ho_adversarial_fn",
        False,
        True,
        False,
        "One broken and one complete path co-exist.",
    )

    # --- partial configs x4 (safe) ---
    add("ho_partial_01.json", _doc([]), "ho_partial", False, False, False, "Empty tool list.")
    add(
        "ho_partial_02.json",
        _doc([_t("bare")]),
        "ho_partial",
        False,
        False,
        False,
        "Tool without permissions.",
    )
    add(
        "ho_partial_03.json",
        _doc([_t("t", {})]),
        "ho_partial",
        False,
        False,
        False,
        "Empty permissions object.",
    )
    add(
        "ho_partial_04.json",
        _doc([_t("t", {"commands": ["ls"]})], [_s(S1, "sensitive")], [_d(E1, "external")]),
        "ho_partial",
        False,
        False,
        False,
        "Sources/dests declared but unreferenced.",
    )

    # --- ambiguous invoke direction x4 ---
    add(
        "ho_amb_01.json",
        _doc(
            [
                _t("reader", {"reads": [S1]}),
                _t("sender", {"sends_to": [E1], "invokes": ["reader"]}),
            ],
            [_s(S1, "sensitive")],
            [_d(E1, "external")],
        ),
        "ho_ambiguous_invoke",
        False,
        False,
        False,
        "Reverse-only invoke: must NOT be silently treated as outward data flow.",
    )
    add(
        "ho_amb_02.json",
        _doc(
            [
                _t("reader", {"reads": [S1], "invokes": ["sender"]}),
                _t("sender", {"sends_to": [E1], "invokes": ["reader"]}),
            ],
            [_s(S1, "sensitive")],
            [_d(E1, "external")],
        ),
        "ho_ambiguous_invoke",
        False,
        True,
        False,
        "Mutual invokes: outward edge exists, so the path counts (documented direction rule).",
    )
    add(
        "ho_amb_03.json",
        _doc(
            [_t("solo", {"reads": [S1], "invokes": ["solo"], "sends_to": [E1]})],
            [_s(S1, "sensitive")],
            [_d(E1, "external")],
        ),
        "ho_ambiguous_invoke",
        True,
        False,
        False,
        "Self-invoke plus direct send: direct path only (cycles never extend paths).",
    )
    add(
        "ho_amb_04.json",
        _doc(
            [
                _t("reader", {"reads": [S1], "invokes": ["archive"]}, desc="Local-only archiver."),
                _t("archive", {"sends_to": [E1]}),
            ],
            [_s(S1, "sensitive")],
            [_d(E1, "external")],
        ),
        "ho_ambiguous_invoke",
        False,
        True,
        False,
        "Harmless-looking description hides a structural path; structure decides.",
    )

    # --- wildcard interplay x4 ---
    add(
        "ho_mix_01.json",
        _doc(
            [_t("op", {"commands": ["*"], "reads": [S1], "sends_to": [E1]})],
            [_s(S1, "sensitive")],
            [_d(E1, "external")],
        ),
        "ho_wildcard_mixed",
        True,
        False,
        True,
        "Wildcard AND direct path both true.",
    )
    add(
        "ho_mix_02.json",
        _doc(
            [
                _t("r", {"commands": ["*"], "reads": [S1], "invokes": ["s"]}),
                _t("s", {"sends_to": [E2]}),
            ],
            [_s(S1, "sensitive")],
            [_d(E2, "external")],
        ),
        "ho_wildcard_mixed",
        False,
        True,
        True,
        "Wildcard AND multi-step path both true.",
    )
    add(
        "ho_mix_03.json",
        _doc([_t("shell", {"commands": ["*"]})], [_s(S1, "sensitive")], [_d(E1, "external")]),
        "ho_wildcard_mixed",
        False,
        False,
        True,
        "Wildcard with no structural path.",
    )
    add(
        "ho_mix_04.json",
        _doc(
            [
                _t("r", {"commands": ["ls"], "reads": [S2], "invokes": ["s"]}),
                _t("s", {"sends_to": [E1]}),
            ],
            [_s(S2, "sensitive")],
            [_d(E1, "external")],
        ),
        "ho_wildcard_mixed",
        False,
        True,
        False,
        "Narrow commands with a true chain.",
    )

    # --- robustness x8 (excluded) ---
    R = {
        "ho_robust_malformed.json": "{ not valid json",
        "ho_robust_missing_version.json": json.dumps({"tools": []}),
        "ho_robust_unknown_field.json": json.dumps(
            {
                "schema_version": "1.1",
                "tools": [{"name": "t", "permissions": {"commands": ["ls"], "exec": True}}],
            }
        ),
        "ho_robust_wrong_type.json": json.dumps(
            {
                "schema_version": "1.1",
                "tools": [{"name": "t", "permissions": {"sends_to": "heldout_partner_api"}}],
            }
        ),
        "ho_robust_dup_tools.json": json.dumps(
            _doc(
                [_t("dup", {"reads": [S1], "sends_to": [E1]}), _t("dup", {"commands": ["ls"]})],
                [_s(S1, "sensitive")],
                [_d(E1, "external")],
            )
        ),
        "ho_robust_dup_dests.json": json.dumps(
            _doc(
                [_t("s", {"reads": [S1], "sends_to": [E1]})],
                [_s(S1, "sensitive")],
                [_d(E1, "external"), _d(E1, "internal")],
            )
        ),
        "ho_robust_undefined_refs.json": json.dumps(
            _doc(
                [
                    _t(
                        "r",
                        {
                            "reads": ["heldout_typo"],
                            "invokes": ["ghost"],
                            "sends_to": ["heldout_typo_dest"],
                        },
                    )
                ]
            )
        ),
        "ho_robust_top_array.json": json.dumps([{"schema_version": "1.1"}]),
    }
    for fname, raw in R.items():
        F[fname] = raw  # type: ignore[assignment]
    return F, L


def main() -> None:
    FIX_DIR.mkdir(parents=True, exist_ok=True)
    fixtures, labels = build()
    for fname in sorted(fixtures):
        content = fixtures[fname]
        text = (
            content
            if isinstance(content, str)
            else json.dumps(content, indent=2, sort_keys=True) + "\n"
        )
        (FIX_DIR / fname).write_text(text, encoding="utf-8")
    for stale in FIX_DIR.glob("*.json"):
        if stale.name not in fixtures:
            stale.unlink()
    doc = {
        "dataset_version": DATASET_VERSION,
        "count_labeled": len(labels),
        "fixtures": dict(sorted(labels.items())),
        "robustness_excluded": sorted(f for f in fixtures if f not in labels),
    }
    (HERE / "labels.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"Wrote {len(fixtures)} fixtures ({len(labels)} labeled) to {FIX_DIR}")


if __name__ == "__main__":
    main()
