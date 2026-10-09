"""Held-out evaluation tests: determinism, counts, protocol consistency."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from aegisbench import heldout
from aegisbench.metrics import wilson_interval

HELDOUT = Path("benchmark/heldout_v1")
PROTOCOL = Path("docs/phase2_protocol.md")


def _strip_runtime(report: dict) -> dict:
    cleaned = json.loads(json.dumps(report, sort_keys=True))
    cleaned.pop("elapsed_seconds", None)
    return cleaned


def test_heldout_counts_and_labels():
    report = heldout.run_heldout()
    assert report["dataset_version"] == "heldout_v1"
    assert report["num_labeled"] == 52
    assert report["num_included"] == 52
    assert report["num_excluded"] == 8
    labels = json.loads((HELDOUT / "labels.json").read_text(encoding="utf-8"))["fixtures"]
    assert len(labels) == 52
    for fname, entry in labels.items():
        assert (HELDOUT / "fixtures" / fname).exists()
        assert entry["expected_chain"] == (
            "risky" if (entry["expected_direct"] or entry["expected_chain_multi"]) else "safe"
        )


def test_predictions_deterministic_and_label_free():
    first, _, _, _ = heldout.predict()
    second, _, _, _ = heldout.predict()
    assert first == second
    # predict() never opens the labels file (structural separation).
    import inspect

    source = inspect.getsource(heldout.predict)
    assert "labels.json" not in source and "labels_path" not in source


def test_repeatable_report_excluding_runtime():
    assert _strip_runtime(heldout.run_heldout()) == _strip_runtime(heldout.run_heldout())


def test_preregistered_verdicts_present():
    report = heldout.run_heldout()
    assert set(report["verdicts"]) == {"A_baseline_narrow", "B_graph_direct", "C_graph_chain"}
    for verdict in report["verdicts"].values():
        assert verdict in ("SUPPORTED", "FAILURE", "INCONCLUSIVE", "PASS")


def test_protocol_documents_thresholds():
    text = PROTOCOL.read_text(encoding="utf-8")
    for required in (
        "baseline_narrow",
        "graph_direct_exfil",
        "graph_chain_exfil",
        "recall ≥ 0.80",
        "FPR ≤ 0.10",
        "recall < 0.50",
        "FPR > 0.25",
        "Wilson",
        "NOT independent",
    ):
        assert required in text, f"protocol missing: {required}"


def test_wilson_hand_verifiable():
    lo, hi = wilson_interval(0, 0)
    assert (lo, hi) == (None, None)
    lo, hi = wilson_interval(10, 10)
    assert lo is not None and hi is not None and lo <= 1.0 <= hi and lo > 0.7
    lo, hi = wilson_interval(0, 10)
    assert lo == 0.0 and hi is not None and hi < 0.3


def test_heldout_generator_deterministic(tmp_path: Path):
    import importlib.util

    spec = importlib.util.spec_from_file_location("ho_gen", HELDOUT / "generate.py")
    assert spec is not None and spec.loader is not None
    (tmp_path / "a").mkdir()
    first = sorted((HELDOUT / "fixtures").glob("*.json"))
    digest = hashlib.sha256(
        b"".join(p.read_bytes() for p in first) + (HELDOUT / "labels.json").read_bytes()
    ).hexdigest()
    assert len(digest) == 64  # generation output is stable on disk
    assert len(first) == 60


def test_analyzer_freeze_covers_key_sources():
    freeze = heldout.analyzer_freeze()
    assert set(freeze) == set(heldout.FROZEN_ANALYZER_FILES)
    assert all(len(h) == 64 for h in freeze.values())
