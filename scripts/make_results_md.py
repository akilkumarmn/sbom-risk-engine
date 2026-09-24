"""Write docs/results.md (Tables 1-3) from the pipeline artifacts, so the
write-up can never drift from the numbers the site shows.

    python -m scripts.make_results_md
"""
from __future__ import annotations

import json

from engine import config


def _p(x, d=1):
    return "n/a" if x is None else f"{100 * x:.{d}f}%"


def _f(x, d=3):
    return "n/a" if x is None else f"{x:.{d}f}"


def main():
    meta = json.loads((config.SITE_DIR / "model_meta.json").read_text())
    bt = json.loads((config.RESULTS_DIR / "backtest.json").read_text())
    synthetic = "synthetic" in meta["data_source"] or "synthetic" in bt["data_source"]
    L = ["# Results", ""]
    if synthetic:
        L += ["> **SYNTHETIC TEST DATA.** These tables were generated from the offline test fixture "
              "(`tests/synthetic.py`), not from NVD/KEV/EPSS. They prove the pipeline runs end to end and mean "
              "nothing about real-world performance. Run `scripts/run_pipeline.sh` (or the nightly `retrain` "
              "workflow) to regenerate this file from the public feeds.", ""]
    c = meta["counts"]
    L += [f"Model: `{meta['algo']}`, trained {meta['trained_at'][:10]}; data source `{meta['data_source']}`; "
          f"KEV catalogue {meta['snapshots'].get('kev_catalog')}; EPSS scores of {str(meta['snapshots'].get('epss_score_date'))[:10]}.", "",
          f"Split by NVD published date: train {c['train']['n']:,} CVEs ({c['train']['kev']} KEV), "
          f"validate {c['val']['n']:,} ({c['val']['kev']}), test {c['test']['n']:,} ({c['test']['kev']}, "
          f"{100 * c['test']['kev_rate']:.2f}%).", "",
          f"## Table 1 — Classifier vs baselines, {meta['split']['test_year']} test year "
          f"(n={c['test']['n']:,}, k={c['test']['kev']} in KEV)", "",
          "| Ranker | AUC-ROC | PR-AUC | Precision@100 | Precision@500 | Recall@1000 | Effort to cover 90% |",
          "| --- | --- | --- | --- | --- | --- | --- |"]
    for r in meta["table1"]:
        L.append(f"| {r['name']} | {_f(r['auc_roc'])} | {_f(r['pr_auc'])} | {_f(r['precision_at_100'])} | "
                 f"{_f(r['precision_at_500'])} | {_f(r['recall_at_1000'])} | {_p(r['effort_to_cover_90'])} |")
    L += ["", "EPSS rows use the current EPSS file (already informed by post-publication exploitation): an optimistic "
          "upper bound. Metrics are expected values under random tie-breaking.", "",
          "![Feature importance](figures/feature_importance.png)", ""]
    fm = bt["frozen_model"]
    L += [f"## Table 2 — Backtest, frozen {bt['freeze_date']}", "",
          f"Answer key: {bt['answer_key']}. Frozen model `{fm['algo']}` trained on {fm['train_years'][0]}-"
          f"{fm['train_years'][1]} with labels as of the freeze date ({fm['kev_train_at_T']} positives), "
          f"{fm['cross_fit_folds']}-fold cross-fitted.", ""]
    for key, case in bt["cases"].items():
        title = f"{case.get('app') or case['name']}" if key != "population" else "all CVEs published before the freeze date"
        L += [f"### {key}: {title} — N={case['n_findings']:,} findings, M={case['later_exploited']} later-exploited, "
              f"{case['known_exploited_at_T']} already in KEV", "",
              "| Ranking method | Mean rank of later-exploited | Precision@10 | Precision@25 | "
              "Effort to cover 50% | Effort to cover 75% | Effort to cover 90% |",
              "| --- | --- | --- | --- | --- | --- | --- |"]
        if case.get("fixture_note"):
            L = L[:-3] + ["", f"*{case['fixture_note']}*", ""] + L[-3:]
        for r in case["table2"]:
            L.append(f"| {r['name']} | {_f(r['mean_rank_later_exploited'], 1)} | {_f(r['precision_at_10'])} | "
                     f"{_f(r['precision_at_25'])} | {_p(r.get('effort_to_cover_50'))} | "
                     f"{_p(r.get('effort_to_cover_75'))} | {_p(r['effort_to_cover_90'])} |")
        if case.get("table2_open_only"):
            o = case["table2_open_only"]
            L += ["", f"Open findings only ({case['known_exploited_at_T']} already-in-KEV findings removed, "
                  f"N={o[0]['n']:,}):", "",
                  "| Ranking method | Mean rank of later-exploited | Precision@10 | Precision@25 | "
                  "Effort to cover 50% | Effort to cover 75% | Effort to cover 90% |",
                  "| --- | --- | --- | --- | --- | --- | --- |"]
            for r in o:
                L.append(f"| {r['name']} | {_f(r['mean_rank_later_exploited'], 1)} | {_f(r['precision_at_10'])} | "
                         f"{_f(r['precision_at_25'])} | {_p(r.get('effort_to_cover_50'))} | "
                         f"{_p(r.get('effort_to_cover_75'))} | {_p(r['effort_to_cover_90'])} |")
        if case.get("epss_scored_only"):
            L.append(f"\nKeeps only CVEs that EPSS scored on {bt['freeze_date']}; "
                     f"{case['excluded_no_epss_at_T']:,} unscored CVEs "
                     f"({case['excluded_no_epss_later_exploited']} later exploited) are excluded, because filling "
                     "them with 0 would put them in one tied block at the bottom of the EPSS ranking.")
        f_ = case.get("epss_floor")
        if f_ and f_.get("n_at_floor", 0) > 1:
            L.append(f"\nEPSS ties: {f_['n_at_floor']:,} findings ({_p(f_['share_at_floor'])}) share the lowest "
                     f"published EPSS score of {f_['value']:.5f}, {f_['later_exploited_at_floor']} of them later "
                     "exploited. EPSS cannot order that block, which is what decides its behaviour at the deepest "
                     "cut-off; at 50% and 75% coverage it is far ahead of CVSS.")
        if case.get("excluded_published_after_T"):
            L.append(f"\nExcluded (published after the freeze date): {', '.join(case['excluded_published_after_T'])}")
        L += ["", f"![coverage {key}](figures/coverage_backtest_{key}.png)", ""]
    L += ["## Table 3 — Ablation on Formula + ML (effort to cover 90%)", "",
          "| Signal removed | " + " | ".join(bt["cases"]) + " |", "| --- |" + " --- |" * len(bt["cases"])]
    names = [a["name"] for a in next(iter(bt["cases"].values()))["ablation"]]
    for i, n in enumerate(names):
        cells = []
        for case in bt["cases"].values():
            a = case["ablation"][i]
            cells.append("n/a" if a["effort_to_cover_90"] is None else
                         f"{_p(a['effort_to_cover_90'])} ({'+' if (a['delta_vs_full'] or 0) >= 0 else ''}{100 * (a['delta_vs_full'] or 0):.1f} pp)")
        L.append(f"| {n} | " + " | ".join(cells) + " |")
    L += ["", "A positive change means removing the signal made the ranking worse (more patching needed). "
          "A negative change means the signal hurt on this case and should be reported as such.", ""]
    if bt.get("headline_note"):
        L += [f"> {bt['headline_note']}", ""]
    (config.ROOT / "docs" / "results.md").write_text("\n".join(L))
    print("wrote docs/results.md")


if __name__ == "__main__":
    main()
