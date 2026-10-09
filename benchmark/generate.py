"""Deterministic generator for the Phase 1 synthetic benchmark.

Run: `python benchmark/generate.py` from the repo root.
Output: `benchmark/dataset/*.json` + `benchmark/labels.json`.

All IDs are inert synthetic tokens (no real systems, credentials, or data).
No fixture content is executed; descriptions are untrusted text.

Labeling assumptions (see benchmark/README.md):
- expected_chain "risky" IFF the fixture explicitly models a directed path
  sensitive_source -> tool -> (tool)* -> external_destination via
  `reads` / `invokes` / `sends_to` IDs. Nothing is inferred from
  descriptions, `commands`, `file_access`, or `network_access`.
- expected_wildcard True IFF any `permissions.commands[]` strips to "*".
- Robustness files have ambiguous or invalid structure and are EXCLUDED
  from primary metrics; the runner reports them separately.
"""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).parent
DATASET_DIR = HERE / "dataset"
DATASET_VERSION = "1.0"

SENS_A = "synthetic_hr_db"
SENS_B = "synthetic_medical_notes"
NONS_A = "synthetic_public_docs"
NONS_B = "synthetic_sample_data"
EXT_A = "synthetic_external_api"
EXT_B = "synthetic_public_webhook"
INT_A = "synthetic_internal_log"
INT_B = "synthetic_team_dashboard"


def _fixture(
    tools,
    sources=None,
    dests=None,
    name="synthetic-agent",
    version="1.1",
):
    doc: dict = {"schema_version": version, "agent_name": name, "tools": tools}
    if sources is not None:
        doc["data_sources"] = sources
    if dests is not None:
        doc["destinations"] = dests
    return doc


def _tool(name, perms=None, desc="Inert synthetic tool."):
    t: dict = {"name": name, "description": desc}
    if perms is not None:
        t["permissions"] = perms
    return t


def _src(sid, sens):
    return {"id": sid, "sensitivity": sens, "description": f"Inert {sid}."}


def _dst(did, trust):
    return {"id": did, "trust": trust, "description": f"Inert {did}."}


def build() -> tuple[dict[str, dict], dict[str, str]]:
    """Return (fixtures, labels). fixtures: filename -> doc or raw text."""
    fixtures: dict[str, dict | str] = {}
    labels: dict[str, dict] = {}

    def add(fname, doc, family, chain, wildcard, rationale, prop):
        fixtures[fname] = doc
        labels[fname] = {
            "family": family,
            "expected_chain": chain,
            "expected_wildcard": wildcard,
            "rationale": rationale,
            "property": prop,
        }

    # 1. wildcard_only x8: exact "*" but no sensitive->external path.
    for n in range(1, 9):
        cmds = ["ls", "*"] if n % 2 else ["*"]
        if n == 7:
            cmds = ["  *  "]
        extra = {}
        if n == 8:  # legacy fields must not create edges
            extra = {"file_access": [SENS_A], "network_access": [EXT_A]}
        add(
            f"wildcard_only_{n:02d}.json",
            _fixture([_tool("tool_shell", {"commands": cmds, **extra})]),
            "wildcard_only",
            "safe",
            True,
            "Exact '*' allowlist present, but no sensitive source or external "
            "destination is modeled, so no chain path exists.",
            "Baseline narrow rule should fire; chain task is negative.",
        )

    # 2. narrow_safe x8.
    narrow_cmds = [["ls", "git status"], ["cat README"], ["ls"], ["git log"]]
    for n in range(1, 9):
        tools = [_tool("tool_shell", {"commands": narrow_cmds[(n - 1) % 4]})]
        sources = dests = None
        if n in (5, 6):
            sources = [_src(NONS_A, "non-sensitive")]
            dests = [_dst(INT_A, "internal")]
            tools.append(_tool("tool_viewer", {"reads": [NONS_A]}))
        add(
            f"narrow_safe_{n:02d}.json",
            _fixture(tools, sources, dests),
            "narrow_safe",
            "safe",
            False,
            "Named commands only; no wildcard and no sensitive->external path.",
            "Both baseline and graph should be negative.",
        )

    # 3. sensitive_read_only x8: reads sensitive, no external send path.
    for n in range(1, 9):
        if n <= 3:
            tools = [_tool("tool_reader", {"reads": [SENS_A]})]
            extra_dests = None
        elif n <= 5:
            tools = [_tool("tool_reader", {"reads": [SENS_A], "sends_to": [INT_A]})]
            extra_dests = [_dst(INT_A, "internal")]
        elif n == 6:
            tools = [
                _tool("tool_reader", {"reads": [SENS_A], "invokes": ["tool_helper"]}),
                _tool("tool_helper", {"commands": ["ls"]}),
            ]
            extra_dests = None
        else:
            tools = [_tool("tool_reader", {"reads": [SENS_B]})]
            extra_dests = [_dst(INT_B, "internal")]
        sources = [_src(SENS_A if n != 7 else SENS_B, "sensitive")]
        add(
            f"sensitive_read_only_{n:02d}.json",
            _fixture(tools, sources, extra_dests),
            "sensitive_read_only",
            "safe",
            False,
            "Sensitive read exists but no tool sends to an external "
            "destination and no invoke chain reaches one.",
            "Graph must not flag read-alone as exfiltration.",
        )

    # 4. direct_exfil x10: one tool reads sensitive + sends external.
    for n in range(1, 11):
        sid = SENS_A if n % 2 else SENS_B
        did = EXT_A if n % 3 else EXT_B
        perms: dict = {"reads": [sid], "sends_to": [did]}
        wildcard = False
        if n in (3, 6, 9):  # a few also carry a wildcard
            perms["commands"] = ["ls", "*"]
            wildcard = True
        else:
            perms["commands"] = ["ls"]
        tools = [_tool("tool_sender", perms)]
        if n in (5, 10):  # benign noise tool
            tools.append(_tool("tool_viewer", {"commands": ["cat"]}))
        add(
            f"direct_exfil_{n:02d}.json",
            _fixture(tools, [_src(sid, "sensitive")], [_dst(did, "external")]),
            "direct_exfil",
            "risky",
            wildcard,
            "Single tool explicitly reads a sensitive source and sends to an external destination.",
            "Graph should flag source->tool->destination path.",
        )

    # 5. chain_exfil x12: reader -> (relay) -> sender.
    for n in range(1, 13):
        sid = SENS_A if n % 2 else SENS_B
        did = EXT_A if n % 3 else EXT_B
        three_hop = n % 3 == 0
        wildcard = n in (4, 8, 12)
        if not three_hop:
            tools = [
                _tool("tool_reader", {"reads": [sid], "invokes": ["tool_sender"]}),
                _tool(
                    "tool_sender",
                    {"sends_to": [did], "commands": (["ls", "*"] if wildcard else ["ls"])},
                ),
            ]
        else:
            tools = [
                _tool("tool_reader", {"reads": [sid], "invokes": ["tool_relay"]}),
                _tool("tool_relay", {"invokes": ["tool_sender"]}),
                _tool(
                    "tool_sender",
                    {"sends_to": [did], "commands": (["*"] if wildcard else ["ls"])},
                ),
            ]
        if n % 4 == 0:  # list sender first to test order independence
            tools = list(reversed(tools))
        if n == 11:  # benign noise
            tools.append(_tool("tool_notes", {"commands": ["echo hi"]}))
        add(
            f"chain_exfil_{n:02d}.json",
            _fixture(tools, [_src(sid, "sensitive")], [_dst(did, "external")]),
            "chain_exfil",
            "risky",
            wildcard,
            "Two/three-tool invoke chain connects a sensitive read to an "
            "external send; no single tool shows the full path.",
            "Graph should flag multi-hop path; baseline misses most.",
        )

    # 6. broken_chain x10: resembles a chain, one link missing.
    variants = [
        ("no_invoke", "Reader and sender exist but no invokes edge connects them."),
        ("wrong_source", "Chain reads a non-sensitive source only."),
        ("wrong_dest", "Chain sends to an internal destination only."),
        ("missing_tool", "Invokes references an undefined tool."),
        ("reversed", "Invoke direction does not carry sensitive data outward."),
    ]
    for n in range(1, 11):
        kind = variants[(n - 1) % 5][0]
        note = variants[(n - 1) % 5][1]
        sid = SENS_A if n % 2 else SENS_B
        if kind == "no_invoke":
            tools = [
                _tool("tool_reader", {"reads": [sid]}),
                _tool("tool_sender", {"sends_to": [EXT_A]}),
            ]
            sources, dests = [_src(sid, "sensitive")], [_dst(EXT_A, "external")]
        elif kind == "wrong_source":
            tools = [
                _tool("tool_reader", {"reads": [NONS_A], "invokes": ["tool_sender"]}),
                _tool("tool_sender", {"sends_to": [EXT_A]}),
            ]
            sources, dests = (
                [_src(NONS_A, "non-sensitive")],
                [_dst(EXT_A, "external")],
            )
        elif kind == "wrong_dest":
            tools = [
                _tool("tool_reader", {"reads": [sid], "invokes": ["tool_sender"]}),
                _tool("tool_sender", {"sends_to": [INT_A]}),
            ]
            sources, dests = ([_src(sid, "sensitive")], [_dst(INT_A, "internal")])
        elif kind == "missing_tool":
            tools = [_tool("tool_reader", {"reads": [sid], "invokes": ["tool_ghost"]})]
            sources, dests = ([_src(sid, "sensitive")], [_dst(EXT_A, "external")])
        else:  # reversed
            tools = [
                _tool("tool_reader", {"reads": [sid]}),
                _tool("tool_sender", {"sends_to": [EXT_A], "invokes": ["tool_reader"]}),
            ]
            sources, dests = ([_src(sid, "sensitive")], [_dst(EXT_A, "external")])
        add(
            f"broken_chain_{n:02d}.json",
            _fixture(tools, sources, dests),
            "broken_chain",
            "safe",
            False,
            note + " No complete sensitive->external directed path exists.",
            "Graph must stay negative despite surface resemblance.",
        )

    # 7. benign_resemblance x8.
    benign_cases = [
        (
            [
                _tool("tool_shell", {"commands": ["ls *"]}),
                _tool("tool_reader", {"reads": [SENS_A]}),
            ],
            [_src(SENS_A, "sensitive")],
            None,
            "Glob 'ls *' is not the exact '*' token; read has no send path.",
        ),
        (
            [
                _tool("tool_shell", {"commands": ["sudo:*"]}),
                _tool("tool_reader", {"reads": [SENS_A], "sends_to": [INT_A]}),
            ],
            [_src(SENS_A, "sensitive")],
            [_dst(INT_A, "internal")],
            "Namespaced 'sudo:*' is out of scope; send is internal only.",
        ),
        (
            [_tool("tool_reader", {"reads": ["synthetic_hr_db_backup"]})],
            [_src(SENS_A, "sensitive")],
            None,
            "Similar ID is not an exact match; undefined reference creates "
            "no edge (typos must not match).",
        ),
        (
            [_tool("tool_mixer", {"reads": [NONS_A], "sends_to": [EXT_A]})],
            [_src(NONS_A, "non-sensitive")],
            [_dst(EXT_A, "external")],
            "External send of non-sensitive data only.",
        ),
        (
            [_tool("tool_chat", {"commands": ["ls"]})],
            [_src(SENS_A, "sensitive")],
            [_dst(EXT_A, "external")],
            "Description-only risk ('sends HR data to external API' in text) "
            "with no capability fields; descriptions are never parsed.",
        ),
        (
            [_tool("tool_legacy", {"file_access": [SENS_A], "network_access": [EXT_A]})],
            [_src(SENS_A, "sensitive")],
            [_dst(EXT_A, "external")],
            "Legacy file_access/network_access never create graph edges.",
        ),
        (
            [_tool("sender", {"commands": ["ls"]})],
            [_src(SENS_A, "sensitive")],
            [_dst(EXT_A, "external")],
            "Tool name 'sender' implies nothing without sends_to.",
        ),
        (
            [
                _tool(
                    "tool_loop", {"reads": [SENS_A], "invokes": ["tool_loop"], "sends_to": [INT_A]}
                )
            ],
            [_src(SENS_A, "sensitive")],
            [_dst(INT_A, "internal")],
            "Self-loop with internal send only; cycles must not FP.",
        ),
    ]
    for n, (tools, sources, dests, note) in enumerate(benign_cases, 1):
        if n == 5:
            tools[0]["description"] = (
                "Sends synthetic_hr_db to synthetic_external_api (inert text; must be ignored)."
            )
        add(
            f"benign_resemblance_{n:02d}.json",
            _fixture(tools, sources, dests),
            "benign_resemblance",
            "safe",
            False,
            note,
            "Graph and baseline must stay negative on lookalikes.",
        )

    # 8. robustness x8 (excluded from primary metrics).
    robust: dict[str, str] = {
        "robust_malformed_01.json": "{ not valid json",
        "robust_missing_version_01.json": json.dumps({"tools": []}),
        "robust_unknown_field_01.json": json.dumps(
            {
                "schema_version": "1.1",
                "tools": [{"name": "t", "permissions": {"commands": ["ls"], "exec": True}}],
            }
        ),
        "robust_wrong_type_01.json": json.dumps(
            {
                "schema_version": "1.1",
                "tools": [{"name": "t", "permissions": {"reads": "synthetic_hr_db"}}],
                "data_sources": [_src(SENS_A, "sensitive")],
            }
        ),
        "robust_dup_tools_01.json": json.dumps(
            {
                "schema_version": "1.1",
                "tools": [_tool("dup", {"commands": ["ls"]}), _tool("dup", {"commands": ["*"]})],
            }
        ),
        "robust_dup_sources_01.json": json.dumps(
            {
                "schema_version": "1.1",
                "tools": [_tool("r", {"reads": [SENS_A]})],
                "data_sources": [_src(SENS_A, "sensitive"), _src(SENS_A, "sensitive")],
            }
        ),
        "robust_undefined_refs_01.json": json.dumps(
            {
                "schema_version": "1.1",
                "tools": [_tool("r", {"reads": ["typo_source"], "sends_to": ["typo_dest"]})],
            }
        ),
        "robust_top_array_01.json": json.dumps([{"schema_version": "1.1"}]),
    }
    for fname, raw in robust.items():
        fixtures[fname] = raw  # type: ignore[assignment]
    return fixtures, labels


def main() -> None:
    DATASET_DIR.mkdir(parents=True, exist_ok=True)
    fixtures, labels = build()
    for fname in sorted(fixtures):
        content = fixtures[fname]
        text = (
            content
            if isinstance(content, str)
            else json.dumps(content, indent=2, sort_keys=True) + "\n"
        )
        (DATASET_DIR / fname).write_text(text, encoding="utf-8")
    # Prune stale files from older runs.
    for existing in DATASET_DIR.glob("*.json"):
        if existing.name not in fixtures:
            existing.unlink()
    label_doc = {
        "dataset_version": DATASET_VERSION,
        "count_labeled": len(labels),
        "fixtures": dict(sorted(labels.items())),
        "robustness_excluded": sorted(f for f in fixtures if f not in labels),
    }
    (HERE / "labels.json").write_text(
        json.dumps(label_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"Wrote {len(fixtures)} fixtures ({len(labels)} labeled) to {DATASET_DIR}")


if __name__ == "__main__":
    main()
