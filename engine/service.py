"""Scoring service shared by the REST API (api/main.py) and tests.

Uses the same exported artifacts as the dashboard (site/model_meta.json and
site/data/cve/<year>.json shards), so API and browser return identical
scores for identical intel. Live EPSS/KEV are optional; snapshots are the
fallback, and the response says which was used.
"""
from __future__ import annotations

import json
import urllib.request
from functools import lru_cache
from pathlib import Path

from . import config
from .enrich import enrich_findings
from .sbom import correlate, normalize_asset_context, parse_cyclonedx, parse_scan
from .scoring import score_all

EPSS_API = "https://api.first.org/data/v1/epss"


class Intel:
    def __init__(self, site_dir: Path = config.SITE_DIR):
        self.site = Path(site_dir)
        self.meta = json.loads((self.site / "model_meta.json").read_text())
        kev_path = self.site / "data" / "kev.json"
        self.kev_snapshot = json.loads(kev_path.read_text()) if kev_path.exists() else {"cves": {}}

    @lru_cache(maxsize=64)
    def shard(self, year: str) -> dict:
        p = self.site / "data" / "cve" / f"{year}.json"
        return json.loads(p.read_text()) if p.exists() else {}

    def row(self, cve: str) -> dict | None:
        parts = cve.split("-")
        r = self.shard(parts[1]).get(cve) if len(parts) > 2 else None
        if r is None:
            return None
        return {"p_model": r[0], "epss": r[1], "kev": bool(r[2]), "poc_github": bool(r[3] & 1),
                "poc_exploitdb": bool(r[3] & 2), "cvss_impact": r[4], "scope_changed": bool(r[5]),
                "cvss_base": r[6], "contrib": r[7]}


def fetch_live_epss(cves: list[str], timeout: float = 10.0) -> dict[str, float] | None:
    out = {}
    try:
        for i in range(0, len(cves), 100):
            url = f"{EPSS_API}?cve={','.join(cves[i:i + 100])}"
            with urllib.request.urlopen(url, timeout=timeout) as r:  # noqa: S310 (fixed https host)
                for d in json.load(r).get("data", []):
                    out[d["cve"]] = float(d["epss"])
            for c in cves[i:i + 100]:
                out.setdefault(c, 0.0)
        return out
    except Exception:  # noqa: BLE001 - network is optional
        return None


def fetch_live_kev(timeout: float = 15.0) -> set[str] | None:
    for url in (config.KEV_URL, config.KEV_MIRROR_URL):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:  # noqa: S310
                return {v["cveID"] for v in json.load(r)["vulnerabilities"]}
        except Exception:  # noqa: BLE001
            continue
    return None


def score_documents(intel: Intel, sbom_text: str, scan_name: str, scan_text: str,
                    ctx_text: str | None = None, fuzzy: bool = False, live: bool = False) -> dict:
    parsed = parse_cyclonedx(json.loads(sbom_text))
    fmt, findings, skipped = parse_scan(scan_name, scan_text)
    matched, unmatched, log = correlate(parsed, findings, fuzzy=fuzzy)
    ctx = normalize_asset_context(json.loads(ctx_text)) if ctx_text else None
    cves = sorted({f["cve_id"] for f in matched})
    epss_live = fetch_live_epss(cves) if live and cves else None
    kev_live = fetch_live_kev() if live else None
    kev_set = kev_live if kev_live is not None else set(intel.kev_snapshot.get("cves", {}))

    def lookup(cve):
        r = intel.row(cve)
        out = dict(r) if r else {}
        out.pop("contrib", None)
        if epss_live is not None and cve in epss_live:
            out["epss"] = epss_live[cve]
        out["kev"] = cve in kev_set
        return out or None

    rows = score_all(enrich_findings(parsed, matched, lookup, ctx, intel.meta.get("prior_p", 0.0)))
    feats, labels = intel.meta["features"], intel.meta.get("feature_labels", {})
    ranked = []
    for r in sorted(rows, key=lambda x: x["ml"]["rank"]):
        shard = intel.row(r["cve_id"])
        ranked.append({
            "rank": r["ml"]["rank"], "cve": r["cve_id"], "component": r["component"], "version": r["version"],
            "risk": round(r["ml"]["risk"], 2), "tier": r["ml"]["tier"],
            "rank_cvss": r["cvss"]["rank"], "rank_formula": r["legacy"]["rank"],
            "score_cvss": r["cvss"]["risk"], "score_formula": r["legacy"]["risk"],
            "p_model": r["p_model"], "p_source": r["p_source"], "epss": r["epss"], "kev": r["kev"],
            "cvss_base": r["cvss_base"], "fanin": r["fanin"], "crit_mult": r["ml"]["crit_mult"],
            "services": [s["name"] for s in r["services"]],
            "top_features": [{"feature": labels.get(feats[i], feats[i]), "contribution": v}
                             for i, v in (shard or {}).get("contrib", [])],
        })
    return {
        "app": parsed["root_name"], "scan_format": fmt, "findings": len(findings), "matched": len(matched),
        "unmatched": len(unmatched), "nessus_skipped_no_cpe": skipped, "correlation_log": log,
        "intel": {"epss": "live" if epss_live is not None else f"snapshot {intel.meta['snapshots'].get('epss_score_date')}",
                  "kev": "live" if kev_live is not None else f"snapshot {intel.kev_snapshot.get('catalogVersion')}",
                  "model": {"algo": intel.meta["algo"], "test_auc": intel.meta["test_auc"],
                            "trained_at": intel.meta["trained_at"], "data_source": intel.meta["data_source"]}},
        "ranked": ranked,
    }
