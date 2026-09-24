"""Day 2: time-frozen backtest (Table 2) and ablation (Table 3).

Question: with only what was knowable on the freeze date T, how much patch
effort does each ranking need to cover 90% of the CVEs that CISA added to
KEV *after* T?

Everything a ranker sees is frozen at T:
  * EPSS          epss_scores-<T>.csv.gz (historical FIRST file)
  * KEV flag      catalogue rows with dateAdded <= T
  * PoC evidence  first PoC date <= T (and, as a model feature, <= 30 days
                  after publication, same as training)
  * P_model       a model RE-TRAINED for the backtest with labels as of T
                  (train 2019..T-2, validate T-1, published date), never the
                  nightly production model, whose labels include the answer key
  * CVSS          today's NVD vector (CVSS is rarely re-scored; stated assumption)
  * Findings      only CVEs published before T can be in a scan taken at T

Cross-fitting: CVEs in the training years are scored by a fold model that
did not see them (5 folds, fold-specific target encoders), so no CVE is ever
scored by a model that was fitted on it. Validation-year CVEs are scored by
the model fitted on the training years only (they are used for early
stopping and Platt calibration, both with labels as of T).

Answer key: KEV rows with dateAdded > T. Rows already in KEV at T are
"known"; they stay in the ranked list (a real team patches them too) and are
reported separately. An "open findings only" variant drops them.

Two cases: each SBOM fixture (blast radius and asset
context in play) and the whole CVE population published before T
(statistically meaningful numbers; no SBOM, so fan-in/asset terms are 0).

    python -m backtest.run_backtest --features data/features.parquet --freeze 2025-01-01 --out site/backtest.json
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.model_selection import KFold  # noqa: E402

from engine import config  # noqa: E402
from engine.enrich import enrich_findings  # noqa: E402
from engine.features import FeatureEncoder, poc_exists, poc_flags  # noqa: E402
from engine.io_utils import read_table  # noqa: E402
from engine.metrics import coverage_curve, effort_to_cover, mean_rank_of_positives, precision_at, recall_at  # noqa: E402
from engine.model import dump_json, fit_gbm  # noqa: E402
from engine.sbom import correlate, normalize_asset_context, parse_cyclonedx, parse_scan  # noqa: E402
from engine.scoring import cvss_score, legacy_score, ml_score  # noqa: E402

RANKERS = {
    "cvss": "CVSS-only",
    "legacy": "Formula (Cap-1 dashboard)",
    "ml": "Formula + ML",
    "epss": "EPSS-only (reference)",
    "model": "ML probability only (diagnostic)",
}
ABLATIONS = [
    ("none", "None (full Formula + ML)"),
    ("model", "ML probability"),
    ("epss", "EPSS"),
    ("kev", "KEV flag"),
    ("fanin", "Blast radius (fan-in)"),
    ("scope", "Scope multiplier"),
    ("asset", "Asset criticality"),
]
COLORS = {"cvss": "#E5484D", "legacy": "#F0883E", "ml": "#35D0BA", "epss": "#8B8BF5", "model": "#9AA4B2"}


# ---------------------------------------------------------------------------
# Frozen, cross-fitted model
# ---------------------------------------------------------------------------
def frozen_model_scores(df: pd.DataFrame, freeze: dt.date, algo: str = "auto", n_folds: int = 5,
                        log=print) -> tuple[np.ndarray, dict]:
    """P(KEV) for every row, from models that only know labels and PoC
    evidence as of `freeze`. Rows in the training years are cross-fitted."""
    T = pd.Timestamp(freeze)
    y_T = (df["kev_date_added"].notna() & (df["kev_date_added"] <= T)).astype(int)
    year = df["published"].dt.year
    val_year = freeze.year - 1
    tr = (year >= config.TRAIN_YEARS[0]) & (year <= val_year - 1) & (df["published"] < T)
    va = (year == val_year) & (df["published"] < T)
    if y_T[tr].sum() == 0 or y_T[va].sum() == 0:
        raise SystemExit("backtest: no KEV positives (as of the freeze date) in the frozen train/val years")
    extra = poc_flags(df, as_of=freeze)  # PoC flags: <=30 days after publication AND <= T

    def fit(train_mask):
        enc = FeatureEncoder().fit(df[train_mask], y_T[train_mask])
        Xtr = enc.transform(df[train_mask], extra[train_mask], oof=True)
        Xva = enc.transform(df[va], extra[va])
        return enc, fit_gbm(Xtr, y_T[train_mask], Xva, y_T[va], algo=algo)

    p = np.full(len(df), np.nan)
    enc_full, model_full = fit(tr)
    others = ~tr.to_numpy()
    p[others] = model_full.predict_proba(enc_full.transform(df[others], extra[others]))
    tr_idx = np.flatnonzero(tr.to_numpy())
    kf = KFold(n_splits=n_folds, shuffle=True, random_state=config.RANDOM_STATE)
    for k, (fit_pos, hold_pos) in enumerate(kf.split(tr_idx)):
        fit_mask = pd.Series(False, index=df.index)
        fit_mask.iloc[tr_idx[fit_pos]] = True
        enc_k, model_k = fit(fit_mask)
        hold = df.index[tr_idx[hold_pos]]
        p[tr_idx[hold_pos]] = model_k.predict_proba(enc_k.transform(df.loc[hold], extra.loc[hold]))
        log(f"  [frozen model] fold {k + 1}/{n_folds} scored {len(hold_pos):,} training-year CVEs out-of-fold")
    info = {"algo": model_full.algo, "label": f"in CISA KEV on or before {freeze.isoformat()}",
            "train_years": [config.TRAIN_YEARS[0], val_year - 1], "val_year": val_year,
            "n_train": int(tr.sum()), "kev_train_at_T": int(y_T[tr].sum()),
            "n_val": int(va.sum()), "kev_val_at_T": int(y_T[va].sum()), "cross_fit_folds": n_folds,
            "features": model_full.features}
    return p, info


# ---------------------------------------------------------------------------
# Per-CVE intel as of T
# ---------------------------------------------------------------------------
def frozen_intel(df: pd.DataFrame, p_model: np.ndarray, freeze: dt.date) -> pd.DataFrame:
    T = pd.Timestamp(freeze)
    poc = poc_exists(df, as_of=freeze)
    out = pd.DataFrame({
        "cve": df["cve"].to_numpy(),
        "published": df["published"].to_numpy(),
        "p_model": p_model,
        "epss": df["epss_t"].fillna(0.0).to_numpy(),
        "epss_scored": df["epss_t"].notna().to_numpy(),
        "kev": (df["kev_date_added"].notna() & (df["kev_date_added"] <= T)).to_numpy(),
        "later_exploited": (df["kev_date_added"].notna() & (df["kev_date_added"] > T)).to_numpy(),
        "kev_date_added": df["kev_date_added"].to_numpy(),
        "poc_github": poc["has_poc_github"].astype(bool).to_numpy(),
        "poc_exploitdb": poc["has_poc_exploitdb"].astype(bool).to_numpy(),
        "cvss_base": df["cvss_base"].to_numpy(),
        "cvss_impact": df["cvss_impact"].to_numpy(),
        "scope_changed": df["cvss_scope_changed"].astype(bool).to_numpy(),
    })
    return out


def _clean(v):
    if isinstance(v, (float, np.floating)) and np.isnan(v):
        return None
    if isinstance(v, np.bool_):
        return bool(v)
    if isinstance(v, np.floating):
        return float(v)
    return v


# ---------------------------------------------------------------------------
# Evaluation helpers
# ---------------------------------------------------------------------------
def rank_metrics(scores: np.ndarray, y: np.ndarray, ks=(10, 25)) -> dict:
    n = len(y)
    etc = effort_to_cover(scores, y, 0.9)
    out = {"n": int(n), "positives": int(y.sum()),
           "effort_to_cover_90": etc,
           "findings_to_cover_90": None if etc is None else etc * n,
           # 90% coverage is decided by the last few positives, so report the
           # shallower cut-offs too: they describe the top of the list, where a
           # team actually works.
           "effort_to_cover_50": effort_to_cover(scores, y, 0.5),
           "effort_to_cover_75": effort_to_cover(scores, y, 0.75),
           "mean_rank_later_exploited": mean_rank_of_positives(scores, y)}
    for k in ks:
        out[f"precision_at_{k}"] = precision_at(scores, y, k) if n else None
        out[f"recall_at_{k}"] = recall_at(scores, y, k)
    return out


def ranker_scores(rows: list[dict], drop: tuple = ()) -> dict[str, np.ndarray]:
    return {
        "cvss": np.array([cvss_score(r)["raw"] for r in rows]),
        "legacy": np.array([legacy_score(r)["raw"] for r in rows]),
        "ml": np.array([ml_score(r, drop)["raw"] for r in rows]),
        "epss": np.array([float(r.get("epss") or 0.0) for r in rows]),
        "model": np.array([float(r.get("p_model") or 0.0) for r in rows]),
    }


def evaluate_rows(rows: list[dict], name: str, use_ctx: bool) -> dict:
    y = np.array([bool(r["later_exploited"]) for r in rows], dtype=int)
    known = np.array([bool(r["kev"]) for r in rows])
    scores = ranker_scores(rows)
    table2 = [{"ranker": k, "name": RANKERS[k], **rank_metrics(scores[k], y)} for k in RANKERS]
    open_mask = ~known
    table2_open = [{"ranker": k, "name": RANKERS[k], **rank_metrics(scores[k][open_mask], y[open_mask])}
                   for k in RANKERS]
    full = rank_metrics(scores["ml"], y)["effort_to_cover_90"]
    ablation = []
    for key, label in ABLATIONS:
        applicable = use_ctx or key not in ("fanin", "asset")
        if not applicable:
            ablation.append({"removed": key, "name": label, "effort_to_cover_90": None, "delta_vs_full": None,
                             "note": "not applicable (no SBOM / asset context in this case)"})
            continue
        s = ranker_scores(rows, () if key == "none" else (key,))["ml"]
        m = rank_metrics(s, y)
        ablation.append({"removed": key, "name": label, "effort_to_cover_90": m["effort_to_cover_90"],
                         "mean_rank_later_exploited": m["mean_rank_later_exploited"],
                         "precision_at_10": m["precision_at_10"],
                         "delta_vs_full": None if (m["effort_to_cover_90"] is None or full is None)
                         else m["effort_to_cover_90"] - full})
    curves = {}
    if y.sum():
        for k in RANKERS:
            xs, ys = coverage_curve(scores[k], y)
            curves[k] = {"x": [round(v, 4) for v in xs], "y": [round(v, 4) for v in ys]}
    # EPSS ties: everything sharing the lowest published score is unordered by
    # EPSS, which is what decides its tail behaviour at the 90% cut-off.
    e = scores["epss"]
    floor = float(e.min()) if len(e) else 0.0
    at_floor = e <= floor + 1e-12
    epss_floor = {"value": floor, "n_at_floor": int(at_floor.sum()),
                  "share_at_floor": float(at_floor.mean()) if len(e) else None,
                  "later_exploited_at_floor": int(y[at_floor].sum())}
    return {"name": name, "n_findings": len(rows), "later_exploited": int(y.sum()),
            "known_exploited_at_T": int(known.sum()), "table2": table2, "table2_open_only": table2_open,
            "ablation": ablation, "coverage": curves, "epss_floor": epss_floor}


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------
def sbom_case(app_dir: Path, intel: pd.DataFrame, freeze: dt.date, prior_p: float) -> dict:
    sbom = json.loads((app_dir / "sbom.cdx.json").read_text())
    scan_path = next(p for p in (app_dir / "trivy.json", app_dir / "scan.nessus", app_dir / "scan.csv") if p.exists())
    parsed = parse_cyclonedx(sbom)
    fmt, findings, skipped = parse_scan(scan_path.name, scan_path.read_text())
    matched, unmatched, corr_log = correlate(parsed, findings, fuzzy=True)
    ctx_path = app_dir / "asset-context.json"
    ctx = normalize_asset_context(json.loads(ctx_path.read_text())) if ctx_path.exists() else None
    idx = intel.set_index("cve")
    T = pd.Timestamp(freeze)
    kept, dropped_future, dropped_unknown = [], [], []
    for f in matched:
        if f["cve_id"] not in idx.index:
            dropped_unknown.append(f["cve_id"])
            continue
        if idx.at[f["cve_id"], "published"] >= T:
            dropped_future.append(f["cve_id"])
            continue
        # CVSS from the NVD feed (guide: "CVSS from the NVD feed"), not the scanner
        rec = idx.loc[f["cve_id"]]
        if not pd.isna(rec["cvss_impact"]):
            f = {**f, "cvss_base": float(rec["cvss_base"]), "cvss_impact": float(rec["cvss_impact"]),
                 "scope_changed": bool(rec["scope_changed"]), "vector_source": "nvd"}
        kept.append(f)

    def lookup(cve):
        if cve not in idx.index:
            return None
        r = idx.loc[cve]
        return {k: _clean(r[k]) for k in ("p_model", "epss", "kev", "poc_github", "poc_exploitdb",
                                          "cvss_impact", "scope_changed", "cvss_base")}

    rows = enrich_findings(parsed, kept, lookup, ctx, prior_p=prior_p)
    for r in rows:
        r["later_exploited"] = bool(idx.at[r["cve_id"], "later_exploited"])
        kd = idx.at[r["cve_id"], "kev_date_added"]
        r["kev_date_added"] = None if pd.isna(kd) else pd.Timestamp(kd).date().isoformat()
    res = evaluate_rows(rows, app_dir.name, use_ctx=True)
    # A fixture generated by scripts/make_backtest_fixture.py carries targets.json:
    # its packages were chosen *because* they contain the answer-key CVEs, so it
    # validates ordering inside a package set rather than standing in for a real
    # application. Say so everywhere the case is reported.
    tgt = app_dir / "targets.json"
    if tgt.exists():
        t = json.loads(tgt.read_text())
        res["constructed"] = True
        res["fixture_note"] = (
            f"Constructed validation fixture, not a real application: {len(t.get('packages', []))} package versions "
            f"pinned to {len(t.get('cves', []))} CVEs that CISA added to KEV after {t.get('freeze', 'the freeze date')}, "
            "selected from OSV affected-version data; the SBOM and scan are genuine Syft and Trivy output over those "
            "manifests, and the dependency tree is one level deep.")
    res.update({
        "app": parsed["root_name"] or app_dir.name, "scan_format": fmt, "components": len(parsed["components"]),
        "scan_findings": len(findings), "matched": len(matched), "unmatched": len(unmatched),
        "nessus_skipped_no_cpe": skipped, "excluded_published_after_T": sorted(set(dropped_future)),
        "excluded_not_in_nvd": sorted(set(dropped_unknown)), "asset_context": ctx is not None,
        "correlation_log": corr_log,
        "later_exploited_cves": sorted({r["cve_id"] for r in rows if r["later_exploited"]}),
        "known_exploited_cves": sorted({r["cve_id"] for r in rows if r["kev"]}),
        "findings": [_finding_summary(r) for r in rows],
    })
    return res


def _finding_summary(r: dict) -> dict:
    return {"cve": r["cve_id"], "component": r["component"], "version": r["version"],
            "cvss_base": r.get("cvss_base"), "epss_T": round(r["epss"], 5), "kev_at_T": r["kev"],
            "p_model": round(r["p_model"], 5), "fanin": r["fanin"], "later_exploited": r["later_exploited"],
            "kev_date_added": r["kev_date_added"],
            "score": {"cvss": cvss_score(r)["raw"], "legacy": round(legacy_score(r)["raw"], 4),
                      "ml": round(ml_score(r)["raw"], 4)}}


def _population_rows(pop: pd.DataFrame) -> list[dict]:
    rows = []
    for rec in pop.itertuples(index=False):
        rows.append({"cve_id": rec.cve, "cvss_base": _clean(rec.cvss_base) or 0.0,
                     "cvss_impact": _clean(rec.cvss_impact) or 0.0, "scope_changed": bool(rec.scope_changed),
                     "epss": float(rec.epss), "kev": bool(rec.kev), "poc_github": bool(rec.poc_github),
                     "poc_exploitdb": bool(rec.poc_exploitdb), "p_model": float(rec.p_model),
                     "fanin": 0, "max_fanin": 0, "services": [], "has_context": False,
                     "later_exploited": bool(rec.later_exploited)})
    return rows


def population_case(intel: pd.DataFrame, freeze: dt.date, epss_scored_only: bool = True) -> dict:
    """Whole-population case.

    EPSS does not publish a score for every CVE. Filling the gaps with 0.0 puts
    tens of thousands of CVEs in one tied block at the bottom of the EPSS
    ranking, which makes the EPSS baseline look close to random and is not what
    a team using EPSS would see. The headline population case therefore keeps
    only CVEs that EPSS scored on the freeze date; the unrestricted numbers are
    still reported alongside, under "all_cves_variant".
    """
    T = pd.Timestamp(freeze)
    base = intel[(intel["published"] < T) & intel["p_model"].notna()]
    pop = base[base["epss_scored"]] if epss_scored_only else base
    res = evaluate_rows(_population_rows(pop), "CVEs published before T and scored by EPSS at T"
                        if epss_scored_only else "all CVEs published before T", use_ctx=False)
    res["published_range"] = [pop["published"].min().date().isoformat(), pop["published"].max().date().isoformat()]
    res["epss_scored_only"] = epss_scored_only
    res["excluded_no_epss_at_T"] = int(len(base) - len(pop))
    res["excluded_no_epss_later_exploited"] = int(base.loc[~base["epss_scored"], "later_exploited"].sum())
    if epss_scored_only:
        other = evaluate_rows(_population_rows(base), "all CVEs published before T (EPSS gaps filled with 0)",
                              use_ctx=False)
        res["all_cves_variant"] = {"n_findings": other["n_findings"], "later_exploited": other["later_exploited"],
                                   "table2": other["table2"], "table2_open_only": other["table2_open_only"]}
    return res


# ---------------------------------------------------------------------------
def figure(case: dict, path: Path, freeze: dt.date):
    if not case["coverage"]:
        return None
    fig, ax = plt.subplots(figsize=(6.5, 5))
    for k in ("cvss", "legacy", "ml", "epss"):
        c = case["coverage"][k]
        ax.plot(c["x"], c["y"], label=RANKERS[k], color=COLORS[k], lw=2.2 if k == "ml" else 1.4)
    ax.axhline(0.9, ls=":", color="grey")
    ax.set_xlabel("Fraction of findings patched (ranked order)")
    ax.set_ylabel("Fraction of later-exploited CVEs covered")
    ax.set_title(f"Backtest, frozen {freeze.isoformat()}: {case['name']}\n"
                 f"N={case['n_findings']:,} findings, M={case['later_exploited']} later-exploited", fontsize=10)
    ax.legend(loc="lower right", fontsize=8)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1.02)
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path.name


def headline(case: dict) -> dict:
    t = {r["ranker"]: r for r in case["table2"]}
    o = {r["ranker"]: r for r in case["table2_open_only"]}
    a = {r["removed"]: r for r in case["ablation"]}
    return {"case": case["name"], "n_findings": case["n_findings"], "later_exploited": case["later_exploited"],
            "known_exploited_at_T": case["known_exploited_at_T"],
            "ours": t["ml"]["effort_to_cover_90"], "cvss": t["cvss"]["effort_to_cover_90"],
            "formula": t["legacy"]["effort_to_cover_90"], "epss": t["epss"]["effort_to_cover_90"],
            "mean_rank_ours": t["ml"]["mean_rank_later_exploited"],
            "mean_rank_cvss": t["cvss"]["mean_rank_later_exploited"],
            "mean_rank_formula": t["legacy"]["mean_rank_later_exploited"],
            "open": {"n": o["ml"]["n"], "later_exploited": o["ml"]["positives"],
                     "ours": o["ml"]["effort_to_cover_90"], "cvss": o["cvss"]["effort_to_cover_90"],
                     "formula": o["legacy"]["effort_to_cover_90"],
                     "p10_ours": o["ml"]["precision_at_10"], "p10_cvss": o["cvss"]["precision_at_10"],
                     "p10_formula": o["legacy"]["precision_at_10"],
                     "mean_rank_ours": o["ml"]["mean_rank_later_exploited"],
                     "mean_rank_cvss": o["cvss"]["mean_rank_later_exploited"]},
            "ablation_ml_pp": a["model"]["delta_vs_full"],
            "coverage_50": {k: t[k]["effort_to_cover_50"] for k in ("cvss", "legacy", "ml", "epss")},
            "coverage_75": {k: t[k]["effort_to_cover_75"] for k in ("cvss", "legacy", "ml", "epss")},
            "epss_floor": case.get("epss_floor")}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--features", type=Path, default=config.DATA_DIR / "features.parquet")
    ap.add_argument("--freeze", default=config.FREEZE_DATE.isoformat())
    ap.add_argument("--fixtures", type=Path, default=config.ROOT / "backtest" / "fixtures")
    ap.add_argument("--primary", default="legacy-java-app", help="fixture used for the dashboard headline")
    ap.add_argument("--results", type=Path, default=config.RESULTS_DIR)
    ap.add_argument("--figures", type=Path, default=config.FIGURES_DIR)
    ap.add_argument("--out", type=Path, default=config.SITE_DIR / "backtest.json")
    ap.add_argument("--algo", default="auto", choices=["auto", "lightgbm", "hist_gradient_boosting"])
    ap.add_argument("--release", default=None, help="override the release stamp (default: git describe)")
    ap.add_argument("--population-all-cves", action="store_true",
                    help="score the whole population, filling missing EPSS with 0 (not the default; see "
                         "population_case)")
    args = ap.parse_args(argv)
    freeze = dt.date.fromisoformat(args.freeze)
    release = args.release or config.release_stamp()  # read before any file is written

    df = read_table(args.features).reset_index(drop=True)
    fmeta_path = Path(args.features).with_name("features_meta.json")
    fmeta = json.loads(fmeta_path.read_text()) if fmeta_path.exists() else {}
    if df["epss_t"].notna().sum() == 0:
        raise SystemExit(f"no EPSS snapshot for {freeze} in the feature table -- run fetch_data with --freeze {freeze}")

    print(f"[backtest] freeze {freeze}: re-training a frozen, cross-fitted model")
    p, model_info = frozen_model_scores(df, freeze, algo=args.algo)
    intel = frozen_intel(df, p, freeze)
    T = pd.Timestamp(freeze)
    prior_p = float(np.nanmedian(p[(df["published"] < T).to_numpy()]))

    cases = {}
    for app_dir in sorted(d for d in args.fixtures.iterdir() if (d / "sbom.cdx.json").exists()):
        print(f"[backtest] SBOM case: {app_dir.name}")
        cases[app_dir.name] = sbom_case(app_dir, intel, freeze, prior_p)
    print("[backtest] population case")
    cases["population"] = population_case(intel, freeze, epss_scored_only=not args.population_all_cves)

    figs = {}
    for key, case in cases.items():
        figs[key] = figure(case, args.figures / f"coverage_backtest_{key}.png", freeze)

    primary = args.primary if args.primary in cases else next(iter(cases))
    small = cases[primary]["later_exploited"] < 5
    report = {
        "schema": 1,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "data_source": fmeta.get("data_source", "unknown"),
        "release": release,
        "freeze_date": freeze.isoformat(),
        "answer_key": f"CISA KEV rows with dateAdded > {freeze.isoformat()}",
        "kev_catalog": (fmeta.get("kev") or {}).get("catalogVersion"),
        "epss_snapshot": (fmeta.get("epss_freeze") or {}).get("score_date"),
        "frozen_model": model_info,
        "assumptions": [
            "CVSS vectors are today's NVD values (CVSS is rarely re-scored after publication).",
            "Only CVEs published before the freeze date are kept in each scan.",
            "Findings already in KEV at the freeze date stay in the ranked list and are reported as known; "
            "table2_open_only drops them.",
            "Metrics are expected values under random tie-breaking (CVSS produces large tied blocks).",
        ],
        "primary_case": primary,
        "headline": headline(cases[primary]),
        "headline_population": headline(cases["population"]),
        "headline_note": ("The primary SBOM has fewer than 5 later-exploited CVEs; quote the population case "
                          "for statistical claims.") if small else None,
        "cases": cases,
        "figures": figs,
    }
    args.results.mkdir(parents=True, exist_ok=True)
    dump_json(report, args.results / "backtest.json")
    with open(args.results / "ablation.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["case", "signal_removed", "effort_to_cover_90", "change_vs_full"])
        for key, case in cases.items():
            for r in case["ablation"]:
                w.writerow([key, r["name"], "" if r["effort_to_cover_90"] is None else f"{r['effort_to_cover_90']:.4f}",
                            "" if r["delta_vs_full"] is None else f"{r['delta_vs_full']:+.4f}"])
    site = {k: v for k, v in report.items() if k != "cases"}
    site["cases"] = {k: {kk: vv for kk, vv in v.items() if kk not in ("findings", "correlation_log")}
                     for k, v in cases.items()}
    dump_json(site, args.out)
    h = report["headline"]
    print(f"[backtest] {primary}: effort to cover 90% of later-exploited -> ours "
          f"{_pct(h['ours'])} vs CVSS {_pct(h['cvss'])} (N={h['n_findings']}, M={h['later_exploited']})")
    hp = report["headline_population"]
    pop = cases["population"]
    print(f"[backtest] population: ours {_pct(hp['ours'])} vs CVSS {_pct(hp['cvss'])} "
          f"(N={hp['n_findings']:,}, M={hp['later_exploited']}); mean rank ours "
          f"{hp['mean_rank_ours']:,.0f} vs CVSS {hp['mean_rank_cvss']:,.0f}" if hp["mean_rank_ours"] else "")
    if pop.get("epss_scored_only"):
        print(f"[backtest] population excludes {pop['excluded_no_epss_at_T']:,} CVEs with no EPSS score on "
              f"{freeze} ({pop['excluded_no_epss_later_exploited']} of them later exploited)")


def _pct(x):
    return "n/a" if x is None else f"{100 * x:.1f}%"


if __name__ == "__main__":
    main()
