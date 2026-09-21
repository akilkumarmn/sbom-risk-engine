"""Day 1: train the KEV exploitation classifier and produce Table 1.

Split (by NVD published date): train 2019-2023, validate 2024, test 2025.
Label: CVE is in CISA KEV as of the catalog snapshot.

Rankers compared on the 2025 test year:
  CVSS base score | EPSS (FIRST) | our model without EPSS | our model with EPSS
plus two diagnostic variants (logistic regression, model with time features).

    python -m train.train --features data/features.parquet --out models/
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from engine import config  # noqa: E402
from engine.features import FeatureEncoder, label_for, poc_flags, time_features  # noqa: E402
from engine.io_utils import read_table  # noqa: E402
from engine.metrics import coverage_curve, ranking_report  # noqa: E402
from engine.model import dump_json, fit_gbm, fit_logistic  # noqa: E402

RANKER_NAMES = {
    "cvss": "CVSS base score",
    "epss": "EPSS (FIRST)",
    "model_no_epss": "Our model, without EPSS",
    "model_with_epss": "Our model, with EPSS",
    "logreg_no_epss": "Logistic regression (explainability baseline)",
    "model_time_features": "Our model + time features (diagnostic)",
}


def splits(df: pd.DataFrame):
    year = df["published"].dt.year
    tr = (year >= config.TRAIN_YEARS[0]) & (year <= config.TRAIN_YEARS[1])
    return tr, year == config.VAL_YEAR, year == config.TEST_YEAR


def snapshot_extra(df: pd.DataFrame, snapshot: dt.date, epss_col: str = "epss_now", as_of: dt.date | None = None):
    extra = poc_flags(df, as_of=as_of)
    extra["epss"] = df[epss_col].fillna(0.0).to_numpy()
    extra = extra.join(time_features(df, snapshot))
    return extra


def evaluate(y, scores: dict[str, np.ndarray]) -> list[dict]:
    rows = []
    for key, s in scores.items():
        r = ranking_report(s, y, ks=(100, 500), recall_ks=(1000,))
        rows.append({"ranker": key, "name": RANKER_NAMES.get(key, key), **r})
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--features", type=Path, default=config.DATA_DIR / "features.parquet")
    ap.add_argument("--out", type=Path, default=config.MODELS_DIR)
    ap.add_argument("--figures", type=Path, default=config.FIGURES_DIR)
    ap.add_argument("--algo", default="auto", choices=["auto", "lightgbm", "hist_gradient_boosting"])
    args = ap.parse_args(argv)

    df = read_table(args.features)
    fmeta_path = Path(args.features).with_name("features_meta.json")
    fmeta = json.loads(fmeta_path.read_text()) if fmeta_path.exists() else {}
    snapshot = dt.date.today()
    y_all = df["kev_date_added"].notna().astype(int)
    tr, va, te = splits(df)
    for name, m in (("train", tr), ("val", va), ("test", te)):
        if m.sum() == 0 or y_all[m].sum() == 0:
            raise SystemExit(f"{name} split is empty or has no KEV positives -- check --years / data")

    extra = snapshot_extra(df, snapshot)
    enc = FeatureEncoder().fit(df[tr], y_all[tr])
    variants = {"model_no_epss": (), "model_with_epss": ("epss",),
                "model_time_features": ("days_since_publish", "published_year")}
    models, X = {}, {}
    for key, include in variants.items():
        Xtr = enc.transform(df[tr], extra[tr], oof=True, include=include)
        Xva = enc.transform(df[va], extra[va], include=include)
        Xte = enc.transform(df[te], extra[te], include=include)
        models[key] = fit_gbm(Xtr, y_all[tr], Xva, y_all[va], algo=args.algo)
        X[key] = (Xtr, Xva, Xte)
        print(f"[train] {key}: {models[key].algo}, best_iteration={models[key].best_iteration}")
    Xtr, Xva, Xte = X["model_no_epss"]
    models["logreg_no_epss"] = fit_logistic(Xtr, y_all[tr], Xva, y_all[va])

    y_te = y_all[te].to_numpy()
    scores = {
        "cvss": df.loc[te, "cvss_base"].fillna(-1.0).to_numpy(),
        "epss": df.loc[te, "epss_now"].fillna(0.0).to_numpy(),
        "model_no_epss": models["model_no_epss"].predict_proba(Xte),
        "model_with_epss": models["model_with_epss"].predict_proba(X["model_with_epss"][2]),
        "logreg_no_epss": models["logreg_no_epss"].predict_proba(Xte),
        "model_time_features": models["model_time_features"].predict_proba(X["model_time_features"][2]),
    }
    table1 = evaluate(y_te, scores)
    has_cvss = df.loc[te, "cvss_missing"].to_numpy() == 0
    table1_subset = evaluate(y_te[has_cvss], {k: v[has_cvss] for k, v in scores.items()})

    primary = models["model_no_epss"]
    imp = primary.importance(Xva, y_all[va])
    importance = sorted(({"feature": f, "label": label_for(f), "value": v} for f, v in imp.items()),
                        key=lambda r: -r["value"])[:15]
    shap_rows = None
    contrib = primary.contributions(Xte)
    if contrib is not None:
        mean_abs = np.abs(contrib).mean(axis=0)
        shap_rows = sorted(({"feature": f, "label": label_for(f), "value": float(v)}
                            for f, v in zip(primary.features, mean_abs)), key=lambda r: -r["value"])[:15]
    lr = models["logreg_no_epss"].estimator.named_steps["logisticregression"]
    coefs = sorted(({"feature": f, "label": label_for(f), "coef": float(c)}
                    for f, c in zip(models["logreg_no_epss"].features, lr.coef_[0])), key=lambda r: -abs(r["coef"]))[:15]

    args.out.mkdir(parents=True, exist_ok=True)
    for key, m in models.items():
        m.save(args.out / f"{key}.pkl")
    enc.save(args.out / "encoder.json")

    t1 = {r["ranker"]: r for r in table1}
    report = {
        "trained_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "snapshot_date": snapshot.isoformat(),
        "data_source": fmeta.get("data_source", "unknown"),
        "algo": primary.algo,
        "split": {"train_years": list(config.TRAIN_YEARS), "val_year": config.VAL_YEAR, "test_year": config.TEST_YEAR,
                  "by": "NVD published date"},
        "counts": {name: {"n": int(m.sum()), "kev": int(y_all[m].sum()),
                          "kev_rate": float(y_all[m].mean())} for name, m in (("train", tr), ("val", va), ("test", te))},
        "features": primary.features,
        "feature_labels": {f: label_for(f) for f in primary.features},
        "calibration": {"method": "platt_on_validation_year", "a": primary.platt_a, "b": primary.platt_b,
                        "val_base_rate": float(y_all[va].mean())},
        "best_iteration": primary.best_iteration,
        "table1": table1,
        "table1_cvss_scored_subset": table1_subset,
        "test_auc": t1["model_no_epss"]["auc_roc"],
        "test_pr_auc": t1["model_no_epss"]["pr_auc"],
        "importance_kind": "gain" if primary.algo == "lightgbm" else "permutation (val PR-AUC)",
        "importance": importance,
        "shap_mean_abs": shap_rows,
        "logreg_coefficients": coefs,
        "features_meta": fmeta,
        "notes": [
            "EPSS baseline and the with-EPSS variant use the *current* EPSS file, which already reflects post-"
            "publication exploitation activity; treat them as an optimistic upper bound. The time-frozen "
            "comparison is the backtest.",
            "Tie-aware metrics: expected values under random tie-breaking (CVSS has large tied blocks).",
        ],
    }
    dump_json(report, args.out / "train_report.json")
    _figures(args.figures, report, y_te, scores)
    print(json.dumps({r["ranker"]: {k: r[k] for k in ("auc_roc", "pr_auc", "effort_to_cover_90")} for r in table1}, indent=2))


def _figures(fig_dir: Path, report: dict, y_te, scores):
    fig_dir.mkdir(parents=True, exist_ok=True)
    rows = report["shap_mean_abs"] or report["importance"]
    kind = "mean |SHAP| (test year)" if report["shap_mean_abs"] else report["importance_kind"]
    fig, ax = plt.subplots(figsize=(7, 5))
    ax.barh([r["label"] for r in rows][::-1], [r["value"] for r in rows][::-1], color="#35D0BA")
    ax.set_title(f"Top-15 features ({kind})")
    fig.tight_layout()
    fig.savefig(fig_dir / "feature_importance.png", dpi=150)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(6.5, 5))
    for key, color in (("cvss", "#E5484D"), ("epss", "#F0883E"), ("model_no_epss", "#35D0BA"), ("model_with_epss", "#4FA8A8")):
        xs, ys = coverage_curve(scores[key], y_te)
        ax.plot(xs, ys, label=RANKER_NAMES[key], color=color)
    ax.axhline(0.9, ls=":", color="grey")
    ax.set_xlabel("Fraction of CVEs patched (ranked order)")
    ax.set_ylabel("Fraction of KEV-listed CVEs covered")
    ax.set_title(f"Coverage, {report['split']['test_year']} test year")
    ax.legend(loc="lower right", fontsize=8)
    fig.tight_layout()
    fig.savefig(fig_dir / "coverage_test_year.png", dpi=150)
    plt.close(fig)


if __name__ == "__main__":
    main()
