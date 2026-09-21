"""CVSS v3.x vector parsing and the exact impact sub-score (FIRST CVSS v3.1
specification, section 7.1). The Cap-1 dashboard *estimated* the impact
sub-score as min(6, 0.6*base) and hard-coded scope=UNCHANGED for scanner
input; both are replaced by the exact values derived from the vector."""
from __future__ import annotations

import math

METRIC_VALUES = {
    "AV": ("N", "A", "L", "P"),
    "AC": ("L", "H"),
    "PR": ("N", "L", "H"),
    "UI": ("N", "R"),
    "S": ("U", "C"),
    "C": ("H", "L", "N"),
    "I": ("H", "L", "N"),
    "A": ("H", "L", "N"),
}
_CIA_WEIGHT = {"H": 0.56, "L": 0.22, "N": 0.0}


def parse_vector(vector: str | None) -> dict[str, str] | None:
    """'CVSS:3.1/AV:N/AC:L/...' -> {'AV': 'N', ...}. Returns None when the
    string is not a complete, valid CVSS v3 base vector."""
    if not vector or not isinstance(vector, str):
        return None
    parts = vector.strip().split("/")
    if parts and parts[0].upper().startswith("CVSS:"):
        if not parts[0].upper().startswith("CVSS:3"):
            return None
        parts = parts[1:]
    out: dict[str, str] = {}
    for p in parts:
        if ":" not in p:
            continue
        k, v = p.split(":", 1)
        k, v = k.strip().upper(), v.strip().upper()
        if k in METRIC_VALUES:
            if v not in METRIC_VALUES[k]:
                return None
            out[k] = v
    return out if len(out) == len(METRIC_VALUES) else None


def impact_subscore(metrics: dict[str, str] | None) -> float | None:
    """Exact CVSS v3 impact sub-score, rounded to one decimal as NVD reports it."""
    if not metrics:
        return None
    iss = 1.0 - (1 - _CIA_WEIGHT[metrics["C"]]) * (1 - _CIA_WEIGHT[metrics["I"]]) * (1 - _CIA_WEIGHT[metrics["A"]])
    if metrics["S"] == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * math.pow(iss - 0.02, 15)
    impact = max(0.0, impact)
    # floor(x*10+0.5)/10 == JavaScript Math.round: identical in site/engine.js
    return math.floor((impact + 1e-9) * 10 + 0.5) / 10


def scope_changed(metrics: dict[str, str] | None) -> bool:
    return bool(metrics) and metrics.get("S") == "C"


def estimate_impact_from_base(base: float | None) -> float:
    """Fallback used only when no vector exists anywhere (the Cap-1 heuristic)."""
    if base is None or (isinstance(base, float) and math.isnan(base)):
        return 0.0
    return min(6.0, math.floor(base * 0.6 * 100 + 0.5) / 100)
