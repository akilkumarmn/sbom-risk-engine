"""Raw sources -> one row per CVE with every label-free feature, plus the
columns the label, baselines and backtest need (KEV date, EPSS now / at T,
first-PoC dates). Label-dependent encoders are fitted later in train.py.

    python -m train.build_features --out data/features.parquet
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path

from engine import config
from engine.features import base_features
from engine.io_utils import write_table
from engine.sources import load_epss, load_exploitdb, load_kev, load_nvd, load_poc_github
from train.fetch_data import parse_years


def build(raw: Path, years: list[int], freeze: str):
    cves = load_nvd(raw / "nvd", years)
    kev, kev_meta = load_kev(raw / "kev.json")
    epss_now, epss_now_meta = load_epss(raw / "epss_current.csv.gz")
    epss_t_path = raw / f"epss_{freeze}.csv.gz"
    epss_t, epss_t_meta = load_epss(epss_t_path) if epss_t_path.exists() else (None, {})
    poc_dir = raw / "poc-in-github"
    gh = load_poc_github(poc_dir) if poc_dir.exists() else None
    edb = load_exploitdb(raw / "exploitdb.csv") if (raw / "exploitdb.csv").exists() else None

    df = base_features(cves, gh, edb)
    df = df.merge(kev, on="cve", how="left")
    df = df.merge(epss_now.rename(columns={"epss": "epss_now", "percentile": "epss_now_pct"}), on="cve", how="left")
    if epss_t is not None:
        df = df.merge(epss_t.rename(columns={"epss": "epss_t", "percentile": "epss_t_pct"}), on="cve", how="left")
    else:
        df["epss_t"] = float("nan")
        df["epss_t_pct"] = float("nan")
    for c in ("epss_now", "epss_now_pct"):
        df[c] = df[c].fillna(0.0)
    df["id_year"] = df["cve"].str.slice(4, 8).astype(int)
    meta = {
        "built_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "n_cves": int(len(df)), "years": [min(years), max(years)],
        "kev": kev_meta, "kev_cves_in_nvd": int(df["kev_date_added"].notna().sum()),
        "epss_current": epss_now_meta, "epss_freeze": epss_t_meta, "freeze_date": freeze,
        "poc_github_cves": int(0 if gh is None else len(gh)), "exploitdb_cves": int(0 if edb is None else len(edb)),
        "cvss_missing": int(df["cvss_missing"].sum()),
    }
    manifest = raw / "manifest.json"
    if manifest.exists():
        meta["fetch"] = json.loads(manifest.read_text())
    if (raw / "SYNTHETIC").exists():
        meta["data_source"] = "synthetic-test-fixture"
    else:
        meta["data_source"] = "public-feeds"
    return df, meta


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--raw-dir", type=Path, default=config.RAW_DIR)
    ap.add_argument("--years", default=f"{config.FIRST_SCORE_YEAR}-{dt.date.today().year}")
    ap.add_argument("--freeze", default=config.FREEZE_DATE.isoformat())
    ap.add_argument("--out", type=Path, default=config.DATA_DIR / "features.parquet")
    args = ap.parse_args(argv)
    df, meta = build(args.raw_dir, parse_years(args.years), args.freeze)
    path = write_table(df, args.out)
    path.with_name("features_meta.json").write_text(json.dumps(meta, indent=2, default=str))
    print(f"{len(df):,} CVEs, {meta['kev_cves_in_nvd']:,} in KEV -> {path}")


if __name__ == "__main__":
    main()
