"""Attach threat intel, model probability, SBOM graph and asset context to
correlated findings. The dashboard does the same in the browser (see
`enrichFindings` in site/dashboard.html); tests/test_parity.py checks both
produce identical scores from identical intel."""
from __future__ import annotations

from typing import Callable

from .sbom import fanin_map, services_for

# lookup(cve) -> {"p_model", "epss", "kev", "poc_github", "poc_exploitdb",
#                 "cvss_impact", "scope_changed", "cvss_base"} or None
Lookup = Callable[[str], dict | None]


def enrich_findings(parsed: dict, matched: list[dict], lookup: Lookup, ctx: dict | None,
                    prior_p: float = 0.0) -> list[dict]:
    fanin = fanin_map(parsed)
    max_fanin = max(fanin.values()) if fanin else 0
    out = []
    for f in matched:
        rec = lookup(f["cve_id"]) or {}
        g = dict(f)
        g["epss"] = float(rec.get("epss") or 0.0)
        g["kev"] = bool(rec.get("kev"))
        g["poc_github"] = bool(rec.get("poc_github"))
        g["poc_exploitdb"] = bool(rec.get("poc_exploitdb"))
        g["p_model"] = float(rec["p_model"]) if rec.get("p_model") is not None else float(prior_p)
        g["p_source"] = "model" if rec.get("p_model") is not None else "prior"
        g["intel_found"] = bool(rec)
        if g["vector_source"] == "none" and rec.get("cvss_impact") is not None:
            g["cvss_impact"] = float(rec["cvss_impact"])
            g["scope_changed"] = bool(rec.get("scope_changed"))
            g["vector_source"] = "nvd"
            if not g.get("cvss_base") and rec.get("cvss_base") is not None:
                g["cvss_base"] = float(rec["cvss_base"])
        g["fanin"] = int(fanin.get(f["component_ref"], 0))
        g["max_fanin"] = int(max_fanin)
        g["services"] = services_for(f, parsed, ctx)
        g["has_context"] = ctx is not None
        out.append(g)
    return out
