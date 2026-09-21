"""The three rankers shown in the dashboard's toggle, plus ablation switches.

  CVSS-only      : 10 * CVSS base
  Formula        : the Cap-1 dashboard formula, reproduced exactly (legacy)
  Formula + ML   : Risk = 100 * L * I * S                      (guide, Day 2)
      L = 0.5*P_model + 0.3*EPSS + 0.2*KEV
      I = (0.5*CVSSimpact/6 + 0.5*fanin/max_fanin) * Crit_asset
      S = 1.15 if CVSS scope changed else 1.0
      Crit_asset = tier multiplier (1.5/1.25/1.0) x 1.2 if internet-facing;
                   1.0 when no asset context is supplied, tier 2 when it is
                   supplied but the finding maps to no service.

Note on the CVSS impact term: the guide writes CVSS_impact/10, but the CVSS
v3 impact sub-score maxes out at 6.0 (see engine/cvss.py), so /10 would cap
the term at 0.6. /6 normalises it to [0, 1], as the Cap-1 dashboard did.
"""
from __future__ import annotations

import math

from .config import FORMULA

ML = FORMULA["ml"]
LEG = FORMULA["legacy"]
ABLATABLE = ("model", "epss", "kev", "fanin", "scope", "asset")


def jsround(x: float, digits: int) -> float:
    """JavaScript Math.round(x*10^d)/10^d, so Python and browser agree bit-for-bit."""
    f = 10 ** digits
    return math.floor(x * f + 0.5) / f


def soft_ceiling(raw: float) -> float:
    start = FORMULA["soft_ceiling_start"]
    if raw <= start:
        return raw
    span = 100.0 - start
    return 100.0 - span * math.exp(-(raw - start) / span)


def tier_for(score: float) -> str:
    t = FORMULA["tiers"]
    return "Critical" if score >= t["Critical"] else "High" if score >= t["High"] else "Medium" if score >= t["Medium"] else "Low"


def cvss_score(f: dict) -> dict:
    s = jsround(float(f.get("cvss_base") or 0.0) * 10, 2)
    return {"raw": s, "risk": s, "tier": tier_for(s)}


def crit_multiplier(f: dict, drop: tuple = ()) -> float:
    if "asset" in drop or not f.get("has_context"):
        return 1.0
    services = f.get("services") or []
    if not services:
        return ML["tier_mult"][str(ML["default_tier"])]
    best = 0.0
    for s in services:
        m = ML["tier_mult"][str(s["tier"])]
        if s.get("internet_facing"):
            m *= ML["internet_facing_mult"]
        if s.get("handles_pii"):
            m *= ML["handles_pii_mult"]
        best = max(best, m)
    return best


def ml_score(f: dict, drop: tuple = ()) -> dict:
    p = 0.0 if "model" in drop else float(f.get("p_model") or 0.0)
    e = 0.0 if "epss" in drop else float(f.get("epss") or 0.0)
    k = 0.0 if "kev" in drop else (1.0 if f.get("kev") else 0.0)
    likelihood = ML["w_model"] * p + ML["w_epss"] * e + ML["w_kev"] * k
    cvss_term = min(1.0, float(f.get("cvss_impact") or 0.0) / ML["cvss_impact_max"])
    max_fanin = float(f.get("max_fanin") or 0.0)
    fanin_term = 0.0 if ("fanin" in drop or max_fanin <= 0) else float(f.get("fanin") or 0.0) / max_fanin
    crit = crit_multiplier(f, drop)
    impact = (ML["w_cvss_impact"] * cvss_term + ML["w_fanin"] * fanin_term) * crit
    scope = 1.0 if "scope" in drop else (ML["scope_changed_mult"] if f.get("scope_changed") else 1.0)
    raw = 100.0 * likelihood * impact * scope
    risk = soft_ceiling(raw)
    return {"likelihood": likelihood, "cvss_term": cvss_term, "fanin_term": fanin_term, "crit_mult": crit,
            "impact": impact, "scope_mult": scope, "raw": raw, "risk": risk, "tier": tier_for(risk)}


def maturity_label(f: dict) -> str:
    if f.get("kev"):
        return "kev"
    if f.get("maturity_override") in ("none", "poc", "weaponized"):
        return f["maturity_override"]
    if f.get("poc_exploitdb"):
        return "weaponized"
    if f.get("poc_github"):
        return "poc"
    return "none"


def legacy_score(f: dict) -> dict:
    """Cap-1 formula, including its intermediate rounding, so the 'Formula'
    row of the backtest is exactly what the old dashboard computed."""
    services = f.get("services") or []
    weights = LEG["criticality_weight"]
    weighted = sum(weights.get(s["criticality"], 0.0) for s in services)
    business = min(1.0, weighted / LEG["business_divisor"])
    fanin = float(f.get("fanin") or 0.0)
    graph = min(1.0, fanin / LEG["fanin_divisor"])
    if services:
        blast = jsround(LEG["business_share"] * business + (1 - LEG["business_share"]) * graph, 3)
    else:
        blast = jsround(graph, 3)
    label = maturity_label(f)
    maturity = LEG["maturity"][label]
    likelihood = jsround(LEG["w_epss"] * float(f.get("epss") or 0.0) + LEG["w_maturity"] * maturity, 4)
    cvss_comp = min(1.0, float(f.get("cvss_impact") or 0.0) / LEG["cvss_impact_max"])
    impact = jsround(LEG["w_cvss_impact"] * cvss_comp + LEG["w_blast"] * blast, 4)
    crosses = len(services) >= 3 or fanin >= 3
    scope = LEG["scope_changed_mult"] if f.get("scope_changed") else (LEG["trust_boundary_mult"] if crosses else 1.0)
    raw = likelihood * impact * 100 * scope
    risk = jsround(soft_ceiling(raw), 2)
    return {"likelihood": likelihood, "impact": impact, "blast_radius": blast, "business_score": business,
            "graph_score": graph, "maturity_label": label, "maturity": maturity, "scope_mult": scope,
            "crosses_trust_boundary": crosses, "raw": raw, "risk": risk, "tier": tier_for(risk)}


def score_all(findings: list[dict]) -> list[dict]:
    """Adds cvss/legacy/ml blocks and a rank per mode (1 = patch first).
    Ties are broken by CVSS base then CVE id so the UI is deterministic;
    evaluation code uses tie-aware metrics instead of these ranks."""
    out = []
    for f in findings:
        out.append({**f, "cvss": cvss_score(f), "legacy": legacy_score(f), "ml": ml_score(f)})
    for mode in ("cvss", "legacy", "ml"):
        order = sorted(range(len(out)), key=lambda i: (-out[i][mode]["raw"], -float(out[i].get("cvss_base") or 0),
                                                       out[i]["cve_id"], out[i].get("component_ref", "")))
        for rank, i in enumerate(order, 1):
            out[i][mode]["rank"] = rank
    return out
