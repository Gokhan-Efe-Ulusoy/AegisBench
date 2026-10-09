"""Binary classification metrics for the benchmark.

Definitions (positive = fixture has >= 1 finding for the evaluated rule):
- TP: expected risky, predicted risky.
- FP: expected safe, predicted risky.
- TN: expected safe, predicted safe.
- FN: expected risky, predicted safe.
- precision = TP / (TP + FP)
- recall = TP / (TP + FN)
- f1 = 2 * precision * recall / (precision + recall)
- false_positive_rate (FPR) = FP / (FP + TN)

Zero denominators return None (not 0.0) so small/synthetic results cannot
be misread as measured zeros. Callers must render None as "n/a".
"""

from __future__ import annotations


def _safe_div(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return numerator / denominator


def wilson_interval(k: int, n: int, z: float = 1.96) -> tuple[float | None, float | None]:
    """Wilson 95 % score interval for a binomial proportion.

    Returns (lower, upper), or (None, None) when n == 0. Describes sampling
    noise only; it does NOT correct construction bias or label leakage.
    """
    if n < 0 or k < 0 or k > n:
        raise ValueError(f"Need 0 <= k <= n, got k={k!r} n={n!r}")
    if n == 0:
        return (None, None)
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / denom
    return (max(0.0, center - half), min(1.0, center + half))


def compute_binary_metrics(tp: int, fp: int, tn: int, fn: int) -> dict[str, int | float | None]:
    """Compute precision/recall/F1/FPR from confusion counts.

    All counts must be non-negative ints. Returns a dict with the raw
    counts plus derived metrics (None where undefined).
    """
    for name, value in (("tp", tp), ("fp", fp), ("tn", tn), ("fn", fn)):
        if not isinstance(value, int) or value < 0:
            raise ValueError(f"{name} must be a non-negative int, got {value!r}")

    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    if precision is None or recall is None or (precision + recall) == 0:
        f1 = None
    else:
        f1 = 2 * precision * recall / (precision + recall)
    fpr = _safe_div(fp, fp + tn)
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "support": tp + fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fpr,
    }
