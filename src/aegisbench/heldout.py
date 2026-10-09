"""Held-out evaluation (Phase 2): preregistered A/B/C comparisons.

Run: `python -m aegisbench.heldout` from the repo root.
Prints a deterministic JSON report to stdout (except `elapsed_seconds`).

Hygiene: `predict()` never reads labels; `score()` reads predictions +
labels. Prediction and dataset hashes are embedded in the report. This set
is author-generated (see benchmark/heldout_v1/README.md), not blind.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from aegisbench.adapters import mcp as mcp_adapter
from aegisbench.analyzers import graph as graph_analyzer
from aegisbench.metrics import compute_binary_metrics, wilson_interval
from aegisbench.parser import FixtureParseError, parse_fixture_file, resolve_scan_root
from aegisbench.rules import broad_permissions

FROZEN_ANALYZER_FILES = (
    "src/aegisbench/models.py",
    "src/aegisbench/parser.py",
    "src/aegisbench/rules/broad_permissions.py",
    "src/aegisbench/analyzers/graph.py",
    "src/aegisbench/metrics.py",
    "src/aegisbench/adapters/mcp.py",
    "src/aegisbench/heldout.py",
)


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def analyzer_freeze() -> dict[str, str]:
    root = repo_root()
    return {name: sha256_file(root / name) for name in FROZEN_ANALYZER_FILES}


def _conf() -> dict[str, int]:
    return {"tp": 0, "fp": 0, "tn": 0, "fn": 0}


def _update(conf: dict[str, int], expected: bool, predicted: bool) -> None:
    if expected and predicted:
        conf["tp"] += 1
    elif not expected and predicted:
        conf["fp"] += 1
    elif not expected and not predicted:
        conf["tn"] += 1
    else:
        conf["fn"] += 1


def predict(
    fixtures_dir: Path | str | None = None,
) -> tuple[dict[str, dict], dict[str, str], float, float]:
    """Run analyzers on fixtures WITHOUT reading labels.

    Returns (predictions, fixture_hashes, baseline_seconds, graph_seconds).
    Predictions map filename -> baseline/direct/multi positives + warnings.
    `fixtures_dir` defaults to the held-out set; external reviewers pass
    their own directory (which must contain no label files).
    """
    root = repo_root()
    default_dir = root / "benchmark" / "heldout_v1" / "fixtures"
    fix_dir = resolve_scan_root(fixtures_dir) if fixtures_dir else resolve_scan_root(default_dir)
    predictions: dict[str, dict] = {}
    hashes: dict[str, str] = {}
    t_base = t_graph = 0.0
    for path in sorted(fix_dir.glob("*.json")):
        hashes[path.name] = sha256_file(path)
        try:
            parsed = parse_fixture_file(path, fix_dir)
        except FixtureParseError as exc:
            predictions[path.name] = {"parse_error": str(exc).replace(str(fix_dir), "<heldout>")}
            continue
        t0 = time.perf_counter()
        base_pos = len(broad_permissions.check(parsed.fixture, parsed.relative_path)) > 0
        t_base += time.perf_counter() - t0
        t0 = time.perf_counter()
        graph = graph_analyzer.build_graph(parsed.fixture)
        paths = graph_analyzer.find_paths(graph, parsed.fixture)
        t_graph += time.perf_counter() - t0
        predictions[path.name] = {
            "baseline_pos": base_pos,
            "graph_direct_pos": any(len(p) == 2 for p in paths),
            "graph_multi_pos": any(3 <= len(p) <= graph_analyzer.MAX_DEPTH for p in paths),
            "graph_path_count": len(paths),
            "graph_warnings": len(graph.warnings),
        }
    return predictions, hashes, t_base, t_graph


def _report(conf: dict[str, int]) -> dict:
    m = compute_binary_metrics(conf["tp"], conf["fp"], conf["tn"], conf["fn"])
    m["recall_ci95"] = wilson_interval(conf["tp"], conf["tp"] + conf["fn"])
    m["fpr_ci95"] = wilson_interval(conf["fp"], conf["fp"] + conf["tn"])
    return m


def _verdict(recall: float | None, fpr: float | None) -> str:
    if recall is None or fpr is None:
        return "INCONCLUSIVE (undefined metric)"
    if recall >= 0.80 and fpr <= 0.10:
        return "SUPPORTED"
    if recall < 0.50 or fpr > 0.25:
        return "FAILURE"
    return "INCONCLUSIVE"


def score(predictions: dict[str, dict], labels_path: Path | str | None = None) -> dict:
    """Score frozen predictions against labels (separate step).

    `labels_path` defaults to the held-out labels. Label IDs with no
    matching prediction entry are a hard error (never silently dropped).
    """
    root = repo_root()
    default_labels = root / "benchmark" / "heldout_v1" / "labels.json"
    labels_file = Path(labels_path) if labels_path else default_labels
    doc = json.loads(labels_file.read_text(encoding="utf-8"))
    labels: dict = doc["fixtures"]

    comps = {
        "A_baseline_narrow": (_conf(), {}, "expected_wildcard", "baseline_pos"),
        "B_graph_direct": (_conf(), {}, "expected_direct", "graph_direct_pos"),
        "C_graph_chain": (_conf(), {}, "expected_chain_multi", "graph_multi_pos"),
    }
    fps: dict[str, list[str]] = {k: [] for k in comps}
    fns: dict[str, list[str]] = {k: [] for k in comps}
    included = 0
    excluded: list[dict[str, str]] = []

    for fname in sorted(set(list(predictions) + list(labels))):
        pred = predictions.get(fname)
        if fname not in labels:
            behavior = "unlabeled robustness file"
            if pred is not None and "parse_error" in pred:
                detail = str(pred["parse_error"])[:200]
                behavior += f"; rejected safely: {detail}"
            elif pred is not None:
                behavior += (
                    f"; parsed ok (baseline={pred['baseline_pos']}, "
                    f"graph_paths={pred['graph_path_count']}, "
                    f"warnings={pred['graph_warnings']})"
                )
            excluded.append({"file": fname, "reason": behavior})
            continue
        if pred is None:
            raise ValueError(
                f"Missing prediction for labeled fixture {fname!r}: "
                "predictions and labels are mismatched; refusing to score."
            )
        if "parse_error" in pred:
            excluded.append({"file": fname, "reason": str(pred["parse_error"])[:200]})
            continue
        entry = labels[fname]
        fam = entry["family"]
        for key, (overall, _fam, label_key, pred_key) in comps.items():
            fam_conf = comps[key][1].setdefault(fam, _conf())
            expected = bool(entry[label_key])
            predicted = bool(pred[pred_key])
            _update(overall, expected, predicted)
            _update(fam_conf, expected, predicted)
            if expected != predicted:
                (fps if predicted else fns)[key].append(fname)
        included += 1

    results = {}
    for key, (overall, by_fam, _, _) in comps.items():
        results[key] = {
            "overall": _report(overall),
            "by_family": {f: _report(c) for f, c in sorted(by_fam.items())},
        }
    verdicts = {}
    for key in ("B_graph_direct", "C_graph_chain"):
        o = results[key]["overall"]
        verdicts[key] = _verdict(o["recall"], o["false_positive_rate"])
    a = results["A_baseline_narrow"]["overall"]
    verdicts["A_baseline_narrow"] = (
        "PASS"
        if a["precision"] is not None
        and a["recall"] is not None
        and a["precision"] >= 0.95
        and a["recall"] >= 0.95
        else "FAILURE"
    )
    return {
        "dataset_version": doc["dataset_version"],
        "num_labeled": len(labels),
        "num_included": included,
        "num_excluded": len(excluded),
        "results": results,
        "verdicts": verdicts,
        "false_positives": {k: sorted(v)[:15] for k, v in sorted(fps.items())},
        "false_negatives": {k: sorted(v)[:15] for k, v in sorted(fns.items())},
        "excluded": sorted(excluded, key=lambda e: e["file"]),
    }


def evaluate_real_mcp() -> dict:
    """Adapt verified real-schema fixtures; report support boundaries."""
    root = repo_root()
    mcp_dir = root / "benchmark" / "real_mcp"
    files_out: list[dict] = []
    for path in sorted(mcp_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            files_out.append({"file": path.name, "status": f"invalid JSON: {exc}"})
            continue
        try:
            adapted = mcp_adapter.adapt_mcp_config(data, source=path.name)
        except mcp_adapter.McpAdapterError as exc:
            files_out.append({"file": path.name, "status": f"rejected: {exc}"})
            continue
        dump = adapted.fixture.model_dump_json()
        secret_leak = "REDACTED_EXAMPLE_NOT_A_REAL_KEY" in dump
        base_n = len(broad_permissions.check(adapted.fixture, path.name))
        graph_n = len(graph_analyzer.check(adapted.fixture, path.name))
        files_out.append(
            {
                "file": path.name,
                "status": "adapted",
                "tools": [t.name for t in adapted.fixture.tools],
                "commands_per_tool": [
                    (t.permissions.commands if t.permissions else None)
                    for t in adapted.fixture.tools
                ],
                "provenance_fields": len(adapted.provenance),
                "unsupported": list(adapted.unsupported),
                "warnings": list(adapted.warnings),
                "baseline_findings": base_n,
                "graph_findings": graph_n,
                "secret_in_fixture_dump": secret_leak,
            }
        )
    return {
        "adapter_version": mcp_adapter.ADAPTER_VERSION,
        "verified_sources": mcp_adapter.VERIFIED_SOURCES,
        "files": files_out,
        "graph_chain_expected": (
            "none: MCP file schema declares no reads/sends_to/invokes semantics"
        ),
    }


def run_heldout() -> dict:
    predictions, hashes, t_base, t_graph = predict()
    pred_hash = hashlib.sha256(json.dumps(predictions, sort_keys=True).encode()).hexdigest()
    scored = score(predictions)
    scored["analyzer_freeze"] = analyzer_freeze()
    scored["fixture_hashes"] = dict(sorted(hashes.items()))
    scored["prediction_hash"] = pred_hash
    scored["analyzer_versions"] = {
        "baseline": "BROAD-CMD-001 v1 (Phase 0, unchanged)",
        "graph": "GRAPH-CHAIN-001 v1 (Phase 1 prototype)",
    }
    scored["elapsed_seconds"] = {"baseline": round(t_base, 6), "graph": round(t_graph, 6)}
    scored["real_mcp"] = evaluate_real_mcp()
    scored["blinding"] = (
        "Author-generated, not independently validated; predictions frozen "
        "(hash above) by code that never reads labels; no tuning on this set."
    )
    return scored


def main() -> None:
    print(json.dumps(run_heldout(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
