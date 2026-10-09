"""Tests for binary metric calculations (hand-verifiable)."""

from __future__ import annotations

import pytest

from aegisbench.metrics import compute_binary_metrics


def test_balanced_example():
    m = compute_binary_metrics(tp=2, fp=1, tn=3, fn=1)
    assert m["precision"] == pytest.approx(2 / 3)
    assert m["recall"] == pytest.approx(2 / 3)
    assert m["f1"] == pytest.approx(2 / 3)
    assert m["false_positive_rate"] == pytest.approx(1 / 4)
    assert m["support"] == 3


def test_perfect_scores():
    m = compute_binary_metrics(tp=5, fp=0, tn=5, fn=0)
    assert m["precision"] == 1.0
    assert m["recall"] == 1.0
    assert m["f1"] == 1.0
    assert m["false_positive_rate"] == 0.0


def test_zero_denominators_yield_none():
    m = compute_binary_metrics(tp=0, fp=0, tn=8, fn=0)
    assert m["precision"] is None  # no predicted positives
    assert m["recall"] is None  # no expected positives
    assert m["f1"] is None
    assert m["false_positive_rate"] == 0.0


def test_no_negatives_fpr_none():
    m = compute_binary_metrics(tp=3, fp=0, tn=0, fn=1)
    assert m["false_positive_rate"] is None


def test_all_zero_none():
    m = compute_binary_metrics(tp=0, fp=0, tn=0, fn=0)
    assert m["precision"] is None
    assert m["recall"] is None
    assert m["f1"] is None
    assert m["false_positive_rate"] is None


def test_invalid_counts_rejected():
    with pytest.raises(ValueError):
        compute_binary_metrics(tp=-1, fp=0, tn=0, fn=0)
    with pytest.raises(ValueError):
        compute_binary_metrics(tp=1.5, fp=0, tn=0, fn=0)  # type: ignore[arg-type]
