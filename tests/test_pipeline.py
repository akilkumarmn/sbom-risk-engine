"""End-to-end on the synthetic fixture: leakage traps never reach the model,
the split is temporal, the backtest is time-frozen."""
import datetime as dt
import json
import shutil
import tempfile
from pathlib import Path

import pandas as pd

from engine.features import FeatureEncoder, poc_flags
from tests.synthetic import generate
from train.build_features import build

_CACHE = {}


def _features():
    if "df" not in _CACHE:
        d = Path(tempfile.mkdtemp())
        generate(d / "raw", per_year=300, seed=11)
        (d / "raw" / "SYNTHETIC").touch()
        _CACHE["df"], _CACHE["meta"] = build(d / "raw", list(range(2013, 2027)), "2025-01-01")
        shutil.rmtree(d)
    return _CACHE["df"], _CACHE["meta"]


def test_rejected_records_dropped_and_meta_stamped():
    df, meta = _features()
    assert not df["cve"].str.endswith("-99999").any()
    assert meta["data_source"] == "synthetic-test-fixture"


def test_leakage_traps_absent_from_feature_matrix():
    df, _ = _features()
    y = df["kev_date_added"].notna().astype(int)
    tr = df["published"].dt.year <= 2023
    enc = FeatureEncoder().fit(df[tr], y[tr])
    X = enc.transform(df, poc_flags(df))
    banned = ("cisa", "ssvc", "exploitadd", "required", "kev_date", "epss", "days_since", "published")
    assert not [c for c in X.columns if any(b in c.lower() for b in banned)], list(X.columns)
    # KEV rows carry a CISA-catalogue reference in the raw feed; it must not be counted
    kev = df[y == 1]
    non = df[y == 0]
    assert abs(kev["ref_total"].mean() - non["ref_total"].mean()) < 1.0


def test_poc_window_blocks_post_kev_pocs():
    df, _ = _features()
    f = poc_flags(df)
    late = df["poc_github_first"] > df["published"] + pd.Timedelta(days=30)
    assert f.loc[late, "poc_github"].sum() == 0
    frozen = poc_flags(df, as_of=dt.date(2025, 1, 1))
    assert frozen.loc[df["poc_github_first"] > pd.Timestamp("2025-01-01"), "poc_github"].sum() == 0


def test_backtest_answer_key_is_after_freeze():
    from backtest.run_backtest import frozen_intel
    df, _ = _features()
    import numpy as np
    intel = frozen_intel(df.reset_index(drop=True), np.zeros(len(df)), dt.date(2025, 1, 1))
    T = pd.Timestamp("2025-01-01")
    assert (intel.loc[intel["later_exploited"], "kev_date_added"] > T).all()
    assert (intel.loc[intel["kev"], "kev_date_added"] <= T).all()
    assert not (intel["kev"] & intel["later_exploited"]).any()
