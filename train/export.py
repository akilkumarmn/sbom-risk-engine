"""Publish the trained model to the static site.

The model scores every CVE in the feature table once (nightly, in CI) and
the dashboard looks results up by CVE ID. Output:

  site/model_meta.json        model card: algorithm, split, Table 1, feature
                              importance, calibration, data snapshot dates
  site/data/cve/<YEAR>.json   one shard per CVE-ID year (lazy-loaded):
                              {"CVE-...": [p_model, epss, kev, poc_mask,
                                           cvss_impact, scope_changed,
                                           cvss_base, [[feature_idx, contribution], x3]]}
  site/data/kev.json          compact KEV snapshot {cve: dateAdded}

Why lookup instead of in-browser inference (the guide suggests m2cgen)?
Scoring needs NVD fields (CVSS vector, CWE, CPE vendor, reference tags,
PoC dates) that a scanner report does not contain, so the browser would
have to download the per-CVE feature vectors anyway. Shipping the model's
output is smaller, keeps the scanner files in the browser (same privacy
guarantee), and allows exact TreeSHAP explanations that m2cgen cannot give.

    python -m train.export --features data/features.parquet --models models/ --site site/
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import shutil
from pathlib import Path

import numpy as np
import pandas as pd

from engine import config
from engine.features import FeatureEncoder, label_for, poc_exists
from engine.io_utils import read_table
from engine.model import TrainedModel, dump_json, top_contributions
from train.train import snapshot_extra

CHUNK = 50_000


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--features", type=Path, default=config.DATA_DIR / "features.parquet")
    ap.add_argument("--models", type=Path, default=config.MODELS_DIR)
    ap.add_argument("--site", type=Path, default=config.SITE_DIR)
    args = ap.parse_args(argv)

    df = read_table(args.features).reset_index(drop=True)
    report = json.loads((args.models / "train_report.json").read_text())
    enc = FeatureEncoder.from_json(json.loads((args.models / "encoder.json").read_text()))
    primary = TrainedModel.load(args.models / "model_no_epss.pkl")
    explainer = primary if primary.algo == "lightgbm" else TrainedModel.load(args.models / "logreg_no_epss.pkl")
    explanation_kind = ("TreeSHAP contributions of the LightGBM model (log-odds)" if primary.algo == "lightgbm" else
                        "logistic-regression contributions coef*z (log-odds); GBM fallback has no native attribution")

    extra = snapshot_extra(df, dt.date.today())
    poc_now = poc_exists(df)
    p = np.empty(len(df))
    contribs: list = [None] * len(df)
    for start in range(0, len(df), CHUNK):
        sl = slice(start, start + CHUNK)
        X = enc.transform(df.iloc[sl], extra.iloc[sl])
        p[sl] = primary.predict_proba(X)
        rows = top_contributions(explainer.contributions(X), explainer.features, k=3)
        contribs[sl] = rows
    # explainer feature indices -> primary feature list (identical lists, asserted)
    assert explainer.features == primary.features, "explainer and model must share features"

    kev = df["kev_date_added"].notna().to_numpy()
    poc_mask = poc_now["has_poc_github"].to_numpy() * 1 + poc_now["has_poc_exploitdb"].to_numpy() * 2
    impact = df["cvss_impact"].to_numpy()
    base = df["cvss_base"].to_numpy()
    scope = df["cvss_scope_changed"].to_numpy()
    shards: dict[int, dict] = {}
    for i, cve in enumerate(df["cve"].to_numpy()):
        year = int(cve[4:8])
        shards.setdefault(year, {})[cve] = [
            _r(p[i], 5), _r(df.at[i, "epss_now"], 5), int(kev[i]), int(poc_mask[i]),
            None if np.isnan(impact[i]) else _r(impact[i], 1), int(bool(scope[i])),
            None if np.isnan(base[i]) else _r(base[i], 1), contribs[i] or []]

    out_dir = args.site / "data" / "cve"
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    sizes = {}
    for year, entries in sorted(shards.items()):
        path = out_dir / f"{year}.json"
        path.write_text(json.dumps(entries, separators=(",", ":")))
        sizes[year] = len(entries)

    kev_rows = df.loc[df["kev_date_added"].notna(), ["cve", "kev_date_added"]]
    fmeta = report.get("features_meta", {})
    kev_doc = {"catalogVersion": (fmeta.get("kev") or {}).get("catalogVersion"),
               "dateReleased": (fmeta.get("kev") or {}).get("dateReleased"),
               "cves": {c: d.date().isoformat() for c, d in zip(kev_rows["cve"], kev_rows["kev_date_added"])}}
    (args.site / "data" / "kev.json").write_text(json.dumps(kev_doc, separators=(",", ":")))

    meta = {
        "schema": 1,
        "data_source": report.get("data_source", "unknown"),
        "trained_at": report["trained_at"],
        "exported_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "algo": report["algo"],
        "label": "CVE listed in CISA KEV",
        "split": report["split"],
        "counts": report["counts"],
        "test_auc": report["test_auc"],
        "test_pr_auc": report["test_pr_auc"],
        "table1": report["table1"],
        "table1_cvss_scored_subset": report["table1_cvss_scored_subset"],
        "importance_kind": report["importance_kind"],
        "importance": report["importance"],
        "shap_mean_abs": report["shap_mean_abs"],
        "calibration": report["calibration"],
        "prior_p": float(np.median(p)),
        "features": primary.features,
        "feature_labels": {f: label_for(f) for f in primary.features},
        "explanation_kind": explanation_kind,
        "shard_format": ["p_model", "epss", "kev", "poc_mask(1=GitHub,2=Exploit-DB)", "cvss_impact",
                         "scope_changed", "cvss_base", "top3[[feature_idx, contribution]]"],
        "shards": {str(k): v for k, v in sizes.items()},
        "snapshots": {
            "nvd_built_at": fmeta.get("built_at"),
            "kev_catalog": (fmeta.get("kev") or {}).get("catalogVersion"),
            "kev_released": (fmeta.get("kev") or {}).get("dateReleased"),
            "epss_score_date": (fmeta.get("epss_current") or {}).get("score_date"),
            "epss_model_version": (fmeta.get("epss_current") or {}).get("model_version"),
        },
        "formula": config.FORMULA,
        "min_test_auc_gate": config.MIN_TEST_AUC,
    }
    dump_json(meta, args.site / "model_meta.json")
    print(f"exported {len(df):,} CVEs in {len(sizes)} shards; test AUC {meta['test_auc']:.3f}")


def _r(x, d):
    x = float(x)
    return None if np.isnan(x) else round(x, d)


if __name__ == "__main__":
    main()
