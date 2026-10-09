"""Benchmark runner: baseline vs graph analyzer on the versioned dataset.

Run: `python -m aegisbench.benchmark` from the repo root.
Prints a deterministic JSON report to stdout (except `elapsed_seconds`,
which varies by machine and must not be asserted in tests).

Task definitions (predetermined, see benchmark/README.md):
- baseline_narrow: baseline positive (>=1 BROAD-CMD-001) vs
  `expected_wildcard`. This is the baseline's intended task.
- baseline_on_chain: baseline positive vs `expected_chain` ("risky").
  Measures what happens when the narrow rule is (mis)applied as a
  general chain detector. Low recall is EXPECTED, not a bug.
- graph_on_chain: graph positive (>=1 GRAPH-CHAIN-001) vs `expected_chain`.
  The graph's intended task.

Coverage expectation (predefined): baseline should score ~perfect on its
narrow task and miss non-wildcard chains; graph should catch modeled
sensitive->external paths (direct + multi-hop) and stay negative on
broken/benign cases. Any deviation is reported, not hidden.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from aegisbench.analyzers import graph as graph_analyzer
from aegisbench.metrics import compute_binary_metrics
from aegisbench.models import BASELINE_ANALYZER_VERSION, GRAPH_ANALYZER_VERSION
from aegisbench.parser import FixtureParseError, parse_fixture_file, resolve_scan_root
from aegisbench.rules import broad_permissions

METRIC_DEFINITIONS = {
    "tp": "Expected risky and predicted risky.",
    "fp": "Expected safe but predicted risky.",
    "tn": "Expected safe and predicted safe.",
    "fn": "Expected risky but predicted safe.",
    "precision": "TP/(TP+FP); None when no predicted positives.",
    "recall": "TP/(TP+FN); None when no expected positives.",
    "f1": "2PR/(P+R); None when undefined.",
    "false_positive_rate": "FP/(FP+TN); None when no expected negatives.",
    "positive_definition": "A fixture is predicted positive iff the analyzer "
    "emits >= 1 finding for it.",
}

LIMITATIONS = [
    "Synthetic, small dataset (64 labeled); not representative of real agents.",
    "A static path is a modeled potential flow, not proof of exploitability.",
    "Labels encode the explicit-ID path definition; typos create no edge.",
    "Runtime varies by machine; only metric fields are deterministic.",
]


def default_paths() -> tuple[Path, Path]:
    root = Path(__file__).resolve().parent.parent.parent
    return root / "benchmark" / "dataset", root / "benchmark" / "labels.json"


def _confusion() -> dict[str, int]:
    return {"tp": 0, "fp": 0, "tn": 0, "fn": 0}


def _update(conf: dict[str, int], expected_risky: bool, predicted: bool) -> None:
    if expected_risky and predicted:
        conf["tp"] += 1
    elif not expected_risky and predicted:
        conf["fp"] += 1
    elif not expected_risky and not predicted:
        conf["tn"] += 1
    else:
        conf["fn"] += 1


def run_benchmark(
    dataset_dir: Path | str | None = None, labels_path: Path | str | None = None
) -> dict:
    default_dataset, default_labels = default_paths()
    dataset_dir = Path(dataset_dir) if dataset_dir else default_dataset
    labels_path = Path(labels_path) if labels_path else default_labels

    label_doc = json.loads(Path(labels_path).read_text(encoding="utf-8"))
    dataset_version: str = label_doc["dataset_version"]
    labels: dict = label_doc["fixtures"]

    root = resolve_scan_root(dataset_dir)
    files = sorted(root.glob("*.json"))

    overall_narrow = _confusion()
    overall_chain_base = _confusion()
    overall_chain_graph = _confusion()
    by_family: dict[str, dict[str, dict[str, int]]] = {}
    fp_examples: dict[str, list[str]] = {
        "baseline_narrow": [],
        "baseline_on_chain": [],
        "graph_on_chain": [],
    }
    fn_examples: dict[str, list[str]] = {
        "baseline_narrow": [],
        "baseline_on_chain": [],
        "graph_on_chain": [],
    }
    included = 0
    excluded: list[dict[str, str]] = []
    graph_warnings = 0

    t_base = 0.0
    t_graph = 0.0

    for path in files:
        fname = path.name
        if fname not in labels:
            excluded.append({"file": fname, "reason": "unlabeled robustness file"})
            continue
        entry = labels[fname]
        family = entry["family"]
        fam = by_family.setdefault(
            family,
            {
                "baseline_narrow": _confusion(),
                "baseline_on_chain": _confusion(),
                "graph_on_chain": _confusion(),
            },
        )
        try:
            parsed = parse_fixture_file(path, root)
        except FixtureParseError as exc:
            excluded.append({"file": fname, "reason": f"parse error: {exc}"})
            continue
        expected_chain_risky = entry["expected_chain"] == "risky"
        expected_wildcard = bool(entry["expected_wildcard"])

        t0 = time.perf_counter()
        base_findings = broad_permissions.check(parsed.fixture, parsed.relative_path)
        t_base += time.perf_counter() - t0

        t0 = time.perf_counter()
        graph_findings = graph_analyzer.check(parsed.fixture, parsed.relative_path)
        t_graph += time.perf_counter() - t0
        graph_warnings += len(graph_analyzer.build_graph(parsed.fixture).warnings)

        base_pos = len(base_findings) > 0
        graph_pos = len(graph_findings) > 0

        _update(overall_narrow, expected_wildcard, base_pos)
        _update(fam["baseline_narrow"], expected_wildcard, base_pos)
        _update(overall_chain_base, expected_chain_risky, base_pos)
        _update(fam["baseline_on_chain"], expected_chain_risky, base_pos)
        _update(overall_chain_graph, expected_chain_risky, graph_pos)
        _update(fam["graph_on_chain"], expected_chain_risky, graph_pos)

        if expected_wildcard != base_pos:
            if base_pos:
                fp_examples["baseline_narrow"].append(fname)
            else:
                fn_examples["baseline_narrow"].append(fname)
        if expected_chain_risky != base_pos:
            if base_pos:
                fp_examples["baseline_on_chain"].append(fname)
            else:
                fn_examples["baseline_on_chain"].append(fname)
        if expected_chain_risky != graph_pos:
            if graph_pos:
                fp_examples["graph_on_chain"].append(fname)
            else:
                fn_examples["graph_on_chain"].append(fname)
        included += 1

    # Robustness detail for excluded/unlabeled files that still parse or fail.
    robustness: list[dict[str, str]] = []
    for item in excluded:
        if item["reason"] != "unlabeled robustness file":
            robustness.append({**item, "behavior": "excluded from metrics"})
            continue
        target = root / item["file"]
        try:
            parsed = parse_fixture_file(target, root)
            n_base = len(broad_permissions.check(parsed.fixture, parsed.relative_path))
            n_graph = len(graph_analyzer.check(parsed.fixture, parsed.relative_path))
            behavior = f"parsed ok (baseline={n_base}, graph={n_graph}); excluded: label undefined"
        except FixtureParseError as exc:
            # Strip the machine-specific dataset root so the report stays
            # deterministic across checkouts; keep the error kind + detail.
            detail = str(exc).replace(str(root), "<dataset>")
            behavior = f"rejected safely: {detail}; excluded: label undefined"
            behavior = behavior[:300]
        robustness.append({"file": item["file"], "reason": item["reason"], "behavior": behavior})
    robustness.sort(key=lambda r: r["file"])

    def _report(conf: dict[str, int]) -> dict:
        return compute_binary_metrics(conf["tp"], conf["fp"], conf["tn"], conf["fn"])

    report = {
        "dataset_version": dataset_version,
        "analyzer_versions": {
            "baseline": BASELINE_ANALYZER_VERSION,
            "graph": GRAPH_ANALYZER_VERSION,
        },
        "num_labeled": len(labels),
        "num_included": included,
        "num_excluded": len(excluded),
        "metric_definitions": METRIC_DEFINITIONS,
        "expected_coverage": {
            "baseline_narrow": (
                "Families with expected_wildcard=true: wildcard_only "
                "plus wildcard-carrying exfil fixtures."
            ),
            "baseline_on_chain": (
                "Only chain fixtures that also carry an exact '*'; misses other chains by design."
            ),
            "graph_on_chain": "direct_exfil + chain_exfil families; negative elsewhere.",
        },
        "results": {
            "baseline_narrow": {
                "overall": _report(overall_narrow),
                "by_family": {
                    f: _report(v["baseline_narrow"]) for f, v in sorted(by_family.items())
                },
                "elapsed_seconds": round(t_base, 6),
            },
            "baseline_on_chain": {
                "overall": _report(overall_chain_base),
                "by_family": {
                    f: _report(v["baseline_on_chain"]) for f, v in sorted(by_family.items())
                },
                "elapsed_seconds": round(t_base, 6),
            },
            "graph_on_chain": {
                "overall": _report(overall_chain_graph),
                "by_family": {
                    f: _report(v["graph_on_chain"]) for f, v in sorted(by_family.items())
                },
                "elapsed_seconds": round(t_graph, 6),
                "graph_warnings": graph_warnings,
            },
        },
        "false_positive_examples": {k: sorted(v)[:10] for k, v in sorted(fp_examples.items())},
        "false_negative_examples": {k: sorted(v)[:10] for k, v in sorted(fn_examples.items())},
        "robustness_report": robustness,
        "known_limitations": LIMITATIONS,
    }
    return report


def main() -> None:
    print(json.dumps(run_benchmark(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
