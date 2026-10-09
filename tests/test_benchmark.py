"""Benchmark runner tests. Runtime fields are excluded from determinism."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from aegisbench.benchmark import run_benchmark
from aegisbench.cli import app

runner = CliRunner()


def _strip_runtime(report: dict) -> dict:
    cleaned = json.loads(json.dumps(report, sort_keys=True))
    for section in cleaned["results"].values():
        section.pop("elapsed_seconds", None)
    return cleaned


def test_benchmark_counts():
    report = run_benchmark()
    assert report["num_labeled"] == 64
    assert report["num_included"] == 64
    assert report["num_excluded"] == 8
    assert report["dataset_version"] == "1.0"
    assert "BROAD-CMD-001" in report["analyzer_versions"]["baseline"]
    assert "GRAPH-CHAIN-001" in report["analyzer_versions"]["graph"]


def test_baseline_narrow_is_perfect():
    overall = run_benchmark()["results"]["baseline_narrow"]["overall"]
    assert (overall["tp"], overall["fp"], overall["tn"], overall["fn"]) == (14, 0, 50, 0)
    assert overall["precision"] == 1.0 and overall["recall"] == 1.0


def test_chain_comparison_values():
    report = run_benchmark()
    base = report["results"]["baseline_on_chain"]["overall"]
    assert (base["tp"], base["fp"], base["tn"], base["fn"]) == (6, 8, 34, 16)
    graph = report["results"]["graph_on_chain"]["overall"]
    assert (graph["tp"], graph["fp"], graph["tn"], graph["fn"]) == (22, 0, 42, 0)
    assert graph["false_positive_rate"] == 0.0


def test_robustness_report_lists_all_excluded():
    report = run_benchmark()
    assert len(report["robustness_report"]) == 8
    assert all("behavior" in r for r in report["robustness_report"])


def test_repeatable_excluding_runtime():
    assert _strip_runtime(run_benchmark()) == _strip_runtime(run_benchmark())


def test_graph_example_bucketing_uses_graph_signal(tmp_path: Path):
    """Regression: graph FP/FN examples must follow graph positivity.

    A fixture labeled safe that the graph flags (while the baseline stays
    quiet) belongs in graph FP examples, not FN examples.
    """
    from aegisbench.benchmark import run_benchmark as run

    fixture = {
        "schema_version": "1.1",
        "tools": [{"name": "s", "permissions": {"reads": ["src"], "sends_to": ["dst"]}}],
        "data_sources": [{"id": "src", "sensitivity": "sensitive"}],
        "destinations": [{"id": "dst", "trust": "external"}],
    }
    (tmp_path / "mismatch.json").write_text(json.dumps(fixture), encoding="utf-8")
    labels = {
        "dataset_version": "test",
        "fixtures": {
            "mismatch.json": {
                "family": "test",
                "expected_chain": "safe",  # deliberately wrong label
                "expected_wildcard": False,
                "rationale": "bucket test",
                "property": "bucket test",
            }
        },
    }
    labels_path = tmp_path / "labels.json"
    labels_path.write_text(json.dumps(labels), encoding="utf-8")
    report = run(dataset_dir=tmp_path, labels_path=labels_path)
    assert report["false_positive_examples"]["graph_on_chain"] == ["mismatch.json"]
    assert report["false_negative_examples"]["graph_on_chain"] == []


def test_phase0_cli_still_compatible():
    safe = Path("tests/fixtures/safe")
    risky = Path("tests/fixtures/risky")
    assert runner.invoke(app, ["scan", str(safe), "--format", "json"]).exit_code == 0
    assert runner.invoke(app, ["scan", str(risky), "--format", "json"]).exit_code == 1
    # Phase 0 fixtures validate under the extended schema too.
    report = run_benchmark()
    assert report["num_included"] == 64  # benchmark unaffected by CLI fixtures
