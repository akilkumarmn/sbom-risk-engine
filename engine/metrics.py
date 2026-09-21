"""Ranking metrics that are fair to tied scores.

CVSS assigns 9.8 to thousands of CVEs. A naive sort breaks those ties by
file order, which can make CVSS look arbitrarily good or bad. Every metric
here is the *exact expected value under uniformly random tie-breaking*:
within a tied block of g items holding h positives, the j-th positive's
expected position is j*(g+1)/(h+1), and expected hits in the first r slots
of the block are r*h/g. With no ties these reduce to the usual definitions
(and to the implementation guide's effort_to_cover)."""
from __future__ import annotations

import math

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score


def _blocks(scores, labels):
    s = np.asarray(scores, dtype=float)
    y = np.asarray(labels, dtype=int)
    s = np.where(np.isnan(s), -np.inf, s)
    order = np.argsort(-s, kind="mergesort")
    s, y = s[order], y[order]
    blocks = []  # (n_before, g, h)
    i, n = 0, len(s)
    while i < n:
        j = i + 1
        while j < n and s[j] == s[i]:
            j += 1
        blocks.append((i, j - i, int(y[i:j].sum())))
        i = j
    return blocks, n, int(y.sum())


def expected_hits_at(scores, labels, k: int) -> float:
    blocks, n, _ = _blocks(scores, labels)
    k = min(k, n)
    hits = 0.0
    for before, g, h in blocks:
        if before + g <= k:
            hits += h
        else:
            hits += (k - before) * h / g if k > before else 0.0
            break
    return hits


def precision_at(scores, labels, k: int) -> float | None:
    n = len(scores)
    if n == 0:
        return None
    k = min(k, n)
    return expected_hits_at(scores, labels, k) / k


def recall_at(scores, labels, k: int) -> float | None:
    pos = int(np.sum(labels))
    return None if pos == 0 else expected_hits_at(scores, labels, k) / pos


def effort_to_cover(scores, labels, frac: float = 0.9) -> float | None:
    """Fraction of all items that must be patched, in ranked order, to cover
    `frac` of the positives (expected position of the ceil(frac*P)-th hit)."""
    blocks, n, pos = _blocks(scores, labels)
    if pos == 0 or n == 0:
        return None
    need = int(math.ceil(frac * pos - 1e-12))
    covered = 0
    for before, g, h in blocks:
        if covered + h >= need:
            j = need - covered
            return (before + j * (g + 1) / (h + 1)) / n
        covered += h
    return 1.0


def mean_rank_of_positives(scores, labels) -> float | None:
    blocks, _, pos = _blocks(scores, labels)
    if pos == 0:
        return None
    return sum(h * (before + (g + 1) / 2.0) for before, g, h in blocks) / pos


def coverage_curve(scores, labels, points: int = 200):
    """x = fraction of items patched, y = expected fraction of positives covered."""
    blocks, n, pos = _blocks(scores, labels)
    if pos == 0 or n == 0:
        return [0.0, 1.0], [0.0, 1.0]
    xs = [0.0]
    ys = [0.0]
    covered = 0.0
    for before, g, h in blocks:  # piecewise-linear inside a tied block
        covered += h
        xs.append((before + g) / n)
        ys.append(covered / pos)
    if len(xs) > points:
        grid = np.linspace(0, 1, points)
        ys = list(np.interp(grid, xs, ys))
        xs = list(grid)
    return [float(x) for x in xs], [float(y) for y in ys]


def ranking_report(scores, labels, ks=(100, 500), recall_ks=(1000,), frac: float = 0.9) -> dict:
    y = np.asarray(labels, dtype=int)
    s = np.nan_to_num(np.asarray(scores, dtype=float), nan=-1e9)
    both = 0 < y.sum() < len(y)
    out = {
        "n": int(len(y)), "positives": int(y.sum()),
        "auc_roc": float(roc_auc_score(y, s)) if both else None,
        "pr_auc": float(average_precision_score(y, s)) if both else None,
        f"effort_to_cover_{int(frac * 100)}": effort_to_cover(s, y, frac),
        "mean_rank_of_positives": mean_rank_of_positives(s, y),
    }
    for k in ks:
        out[f"precision_at_{k}"] = precision_at(s, y, k)
    for k in recall_ks:
        out[f"recall_at_{k}"] = recall_at(s, y, k)
    return out
