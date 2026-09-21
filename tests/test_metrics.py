"""Tie-aware ranking metrics."""
import numpy as np

from engine.metrics import effort_to_cover, expected_hits_at, mean_rank_of_positives, precision_at


def _guide_effort(ranked_labels, frac=0.9):  # the implementation guide's reference function
    need, hits = int(np.ceil(frac * sum(ranked_labels))), 0
    for i, y in enumerate(ranked_labels, 1):
        hits += y
        if hits >= need:
            return i / len(ranked_labels)
    return 1.0


def test_no_ties_equals_guide_definition():
    rng = np.random.default_rng(0)
    for _ in range(50):
        s = rng.permutation(40).astype(float)
        y = (rng.random(40) < 0.2).astype(int)
        if y.sum() == 0:
            continue
        order = np.argsort(-s)
        assert abs(effort_to_cover(s, y) - _guide_effort(list(y[order]))) < 1e-12


def test_ties_are_expected_values():
    s = np.ones(10)
    y = np.array([1, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    assert abs(expected_hits_at(s, y, 5) - 0.5) < 1e-12
    assert abs(mean_rank_of_positives(s, y) - 5.5) < 1e-12
    assert abs(precision_at(s, y, 2) - 0.1) < 1e-12
    # brute-force: average over all tie-breaks equals the closed form
    rng = np.random.default_rng(1)
    s = rng.integers(0, 3, 12).astype(float)
    y = (rng.random(12) < 0.4).astype(int)
    y[0] = 1
    sims = []
    for _ in range(20000):
        order = np.lexsort((rng.random(12), -s))
        sims.append(_guide_effort(list(y[order])))
    assert abs(np.mean(sims) - effort_to_cover(s, y)) < 0.01
