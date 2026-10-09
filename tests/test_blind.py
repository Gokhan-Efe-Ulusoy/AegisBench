"""Tests for the blinded harness and freeze manifest."""

from __future__ import annotations

import inspect
import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aegisbench import blind, freeze, heldout

runner = CliRunner()
HELDOUT_FIX = Path("benchmark/heldout_v1/fixtures")
HELDOUT_LABELS = Path("benchmark/heldout_v1/labels.json")


def test_predict_never_opens_label_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # Mirrors real layout: labels live BESIDE the fixtures dir, never inside it.
    fix_dir = tmp_path / "fix"
    fix_dir.mkdir()
    (fix_dir / "a.json").write_text(
        json.dumps({"schema_version": "1.0", "tools": []}), encoding="utf-8"
    )
    (tmp_path / "labels.json").write_text("AUTHORITATIVE LABELS {{{", encoding="utf-8")
    real_read_text = Path.read_text

    def guarded(self: Path, *args, **kwargs):
        if "label" in self.name:
            raise AssertionError(f"predict opened a label file: {self}")
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded)
    predictions, hashes, _, _ = heldout.predict(fixtures_dir=fix_dir)
    assert set(predictions) == {"a.json"}
    assert set(hashes) == {"a.json"}
    source = inspect.getsource(heldout.predict)
    assert "labels.json" not in source and "labels_path" not in source


def test_predict_score_roundtrip_matches_heldout():
    predictions, _, _, _ = heldout.predict()
    report = heldout.score(predictions)
    assert report["num_included"] == 52
    assert report["verdicts"]["C_graph_chain"] == "SUPPORTED"


def test_score_rejects_mismatched_ids(tmp_path: Path):
    predictions, _, _, _ = heldout.predict()
    labels = json.loads(HELDOUT_LABELS.read_text(encoding="utf-8"))
    labels["fixtures"]["ghost_missing.json"] = {
        "family": "x",
        "expected_chain": "safe",
        "expected_direct": False,
        "expected_chain_multi": False,
        "expected_wildcard": False,
        "rationale": "x",
    }
    bad = tmp_path / "labels.json"
    bad.write_text(json.dumps(labels), encoding="utf-8")
    with pytest.raises(ValueError, match="Missing prediction"):
        heldout.score(predictions, labels_path=bad)


def test_blind_cli_predict_and_score(tmp_path: Path):
    pred_file = tmp_path / "pred.json"
    result = runner.invoke(
        blind.app, ["predict", "--fixtures", str(HELDOUT_FIX), "--out", str(pred_file)]
    )
    assert result.exit_code == 0, result.output
    assert pred_file.exists()
    result = runner.invoke(
        blind.app, ["score", "--predictions", str(pred_file), "--labels", str(HELDOUT_LABELS)]
    )
    assert result.exit_code == 0, result.output
    assert "SUPPORTED" in result.output


def test_blind_cli_score_mismatch_exits_2(tmp_path: Path):
    pred_file = tmp_path / "pred.json"
    assert (
        runner.invoke(
            blind.app, ["predict", "--fixtures", str(HELDOUT_FIX), "--out", str(pred_file)]
        ).exit_code
        == 0
    )
    labels = json.loads(HELDOUT_LABELS.read_text(encoding="utf-8"))
    labels["fixtures"]["ghost.json"] = {
        "family": "x",
        "expected_chain": "safe",
        "expected_direct": False,
        "expected_chain_multi": False,
        "expected_wildcard": False,
        "rationale": "x",
    }
    bad = tmp_path / "labels.json"
    bad.write_text(json.dumps(labels), encoding="utf-8")
    result = runner.invoke(
        blind.app, ["score", "--predictions", str(pred_file), "--labels", str(bad)]
    )
    assert result.exit_code == 2
    assert "mismatched" in result.output


def test_freeze_covers_everything_and_is_deterministic():
    first = freeze.build_freeze()
    second = freeze.build_freeze()
    assert first == second
    assert first["missing"] == []
    assert len(first["files"]) >= 160
    # Contract: the manifest records the interpreter that generated it,
    # using the same normalization as freeze.build_freeze.
    assert first["python"] == sys.version.split()[0]
    assert "docs/reproducibility_manifest.md" not in first["files"]  # excluded: embeds hashes
    assert "src/aegisbench/analyzers/graph.py" in first["files"]
