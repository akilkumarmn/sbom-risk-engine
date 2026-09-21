"""Feature engineering. Two stages:

1. `base_features(cves)` - everything that does not depend on labels
   (CVSS one-hots, reference counts, keyword flags, PoC timing). Deterministic.
2. `FeatureEncoder` - the label-dependent parts (top-30 CWE list and the
   vendor/product KEV-rate target encoding). It is *fitted on training rows
   only*; training rows get out-of-fold encodings so a row never sees its own
   label, everything else gets the full-training-set encoding.
"""
from __future__ import annotations

import datetime as dt
import json
import re

import numpy as np
import pandas as pd
from sklearn.model_selection import KFold

from . import config
from .cvss import METRIC_VALUES, parse_vector

ONEHOT_COLS = [f"{m.lower()}_{v}" for m, vals in METRIC_VALUES.items() for v in vals]
REF_COLS = ["ref_total", "ref_exploit", "ref_patch", "ref_vendor_advisory", *config.EXPLOIT_DOMAINS.keys()]
KW_COLS = list(config.KEYWORDS.keys())
POC_COLS = ["poc_github", "poc_exploitdb"]
TIME_COLS = ["days_since_publish", "published_year"]

FEATURE_LABELS = {
    "cvss_base": "CVSS base score", "cvss_missing": "No CVSS v3 vector",
    "av_N": "Network attack vector", "av_A": "Adjacent attack vector", "av_L": "Local attack vector",
    "av_P": "Physical attack vector", "ac_L": "Low attack complexity", "ac_H": "High attack complexity",
    "pr_N": "No privileges required", "pr_L": "Low privileges required", "pr_H": "High privileges required",
    "ui_N": "No user interaction", "ui_R": "User interaction required",
    "s_U": "Scope unchanged", "s_C": "Scope changed",
    "c_H": "High confidentiality impact", "c_L": "Low confidentiality impact", "c_N": "No confidentiality impact",
    "i_H": "High integrity impact", "i_L": "Low integrity impact", "i_N": "No integrity impact",
    "a_H": "High availability impact", "a_L": "Low availability impact", "a_N": "No availability impact",
    "vendor_kev_rate": "Vendor's historical KEV rate", "product_kev_rate": "Product's historical KEV rate",
    "ref_total": "Number of references", "ref_exploit": "References tagged Exploit",
    "ref_patch": "References tagged Patch", "ref_vendor_advisory": "Vendor advisories",
    "dom_exploitdb": "Exploit-DB reference", "dom_github": "GitHub reference",
    "dom_packetstorm": "Packet Storm reference", "dom_zdi": "ZDI reference",
    "poc_github": "Public PoC on GitHub (<=30d)", "poc_exploitdb": "Exploit-DB entry (<=30d)",
    "desc_len": "Description length", "kw_rce": "Mentions code execution",
    "kw_unauth": "Mentions unauthenticated", "kw_deser": "Mentions deserialization",
    "kw_ssrf": "Mentions SSRF", "kw_auth_bypass": "Mentions authentication bypass",
    "epss": "EPSS score", "days_since_publish": "Days since publication", "published_year": "Publication year",
    "cwe_other": "Other CWE",
}


def label_for(feature: str) -> str:
    if feature in FEATURE_LABELS:
        return FEATURE_LABELS[feature]
    if feature.startswith("cwe_"):
        return feature.replace("cwe_", "CWE-")
    return feature


def base_features(cves: pd.DataFrame, poc_github: pd.Series | None, poc_exploitdb: pd.Series | None) -> pd.DataFrame:
    """cves: output of sources.load_nvd. Returns cves plus label-free features.
    PoC *dates* are attached; PoC *flags* are derived per snapshot by
    `poc_flags` so the backtest can freeze them at T."""
    df = cves.copy()
    parsed = df["cvss_vector"].map(parse_vector)
    df["cvss_missing"] = parsed.isna().astype(np.int8)
    for m, vals in METRIC_VALUES.items():
        col_vals = parsed.map(lambda p, m=m: p[m] if p else None)
        for v in vals:
            df[f"{m.lower()}_{v}"] = (col_vals == v).astype(np.int8)
    df["cvss_scope_changed"] = df["s_C"].astype(bool)
    desc = df["description"].fillna("").str.lower()
    df["desc_len"] = desc.str.len().astype(np.int32)
    for col, pattern in config.KEYWORDS.items():
        df[col] = desc.str.contains(pattern, regex=True, flags=re.IGNORECASE).astype(np.int8)
    for col in REF_COLS:
        df[col] = df[col].fillna(0).astype(np.int16)
    empty = pd.Series(dtype="datetime64[ns]")
    df["poc_github_first"] = df["cve"].map(poc_github if poc_github is not None else empty)
    df["poc_exploitdb_first"] = df["cve"].map(poc_exploitdb if poc_exploitdb is not None else empty)
    df["published_year"] = df["published"].dt.year.astype(np.int16)
    return df


def poc_flags(df: pd.DataFrame, as_of: dt.date | None = None, window_days: int = config.POC_WINDOW_DAYS) -> pd.DataFrame:
    """PoC appeared within `window_days` of publication (and, if `as_of` is
    given, on or before `as_of`). Returns a frame with POC_COLS."""
    out = pd.DataFrame(index=df.index)
    limit = df["published"] + pd.Timedelta(days=window_days)
    if as_of is not None:
        limit = limit.clip(upper=pd.Timestamp(as_of))
    for col, src in (("poc_github", "poc_github_first"), ("poc_exploitdb", "poc_exploitdb_first")):
        first = df[src]
        out[col] = (first.notna() & (first <= limit)).astype(np.int8)
    return out


def poc_exists(df: pd.DataFrame, as_of: dt.date | None = None) -> pd.DataFrame:
    """Unwindowed: did any public PoC exist at `as_of` (or today)? Used for
    the legacy formula's 'exploit maturity' only, never as a model feature."""
    ts = pd.Timestamp(as_of) if as_of else pd.Timestamp.today().normalize() + pd.Timedelta(days=1)
    return pd.DataFrame({
        "has_poc_github": (df["poc_github_first"].notna() & (df["poc_github_first"] <= ts)).astype(np.int8),
        "has_poc_exploitdb": (df["poc_exploitdb_first"].notna() & (df["poc_exploitdb_first"] <= ts)).astype(np.int8),
    }, index=df.index)


def time_features(df: pd.DataFrame, snapshot: dt.date) -> pd.DataFrame:
    return pd.DataFrame({
        "days_since_publish": (pd.Timestamp(snapshot) - df["published"]).dt.days.clip(lower=0).astype(np.int32),
        "published_year": df["published_year"].astype(np.int16),
    }, index=df.index)


class FeatureEncoder:
    """Label-dependent encoders, fitted on training rows only."""

    def __init__(self, top_cwes: int = config.TOP_CWES, smoothing: float = config.TARGET_ENCODING_SMOOTHING,
                 n_folds: int = config.N_FOLDS, random_state: int = config.RANDOM_STATE):
        self.top_cwes_n = top_cwes
        self.m = smoothing
        self.n_folds = n_folds
        self.random_state = random_state
        self.cwes: list[str] = []
        self.prior = 0.0
        self.tables: dict[str, dict[str, float]] = {}
        self.fold_of: dict[str, int] = {}

    # -- fitting ---------------------------------------------------------
    def fit(self, train: pd.DataFrame, y: pd.Series) -> "FeatureEncoder":
        y = y.astype(float)
        real = train["cwe"][train["cwe"].str.startswith("CWE-")]
        self.cwes = real.value_counts().head(self.top_cwes_n).index.tolist()
        self.prior = float(y.mean())
        self.tables = {col: self._rate_table(train[col], y) for col in ("vendor", "product")}
        kf = KFold(n_splits=self.n_folds, shuffle=True, random_state=self.random_state)
        self.fold_of = {}
        cves = train["cve"].to_numpy()
        for k, (_, idx) in enumerate(kf.split(cves)):
            for c in cves[idx]:
                self.fold_of[c] = k
        self._oof = {}
        for col in ("vendor", "product"):
            oof = pd.Series(np.nan, index=train.index)
            for k in range(self.n_folds):
                in_fold = train["cve"].map(self.fold_of) == k
                table = self._rate_table(train.loc[~in_fold, col], y[~in_fold])
                oof[in_fold] = train.loc[in_fold, col].map(table)
            self._oof[col] = oof.fillna(self.prior)
        self._train_index = train.index
        return self

    def _rate_table(self, keys: pd.Series, y: pd.Series) -> dict[str, float]:
        prior = float(y.mean()) if len(y) else self.prior
        g = pd.DataFrame({"k": keys.to_numpy(), "y": y.to_numpy()}).groupby("k")["y"].agg(["sum", "count"])
        rate = (g["sum"] + self.m * prior) / (g["count"] + self.m)
        return rate.to_dict()

    # -- transforming ----------------------------------------------------
    def transform(self, df: pd.DataFrame, extra: pd.DataFrame | None = None, oof: bool = False,
                  include: tuple[str, ...] = ()) -> pd.DataFrame:
        """Assemble the model matrix. `oof=True` only for the exact training
        frame passed to fit(). `extra` supplies snapshot-dependent columns
        (poc flags, epss, time features)."""
        X = pd.DataFrame(index=df.index)
        X["cvss_base"] = df["cvss_base"].fillna(-1.0).astype(float)
        X["cvss_missing"] = df["cvss_missing"].astype(np.int8)
        for c in ONEHOT_COLS:
            X[c] = df[c].astype(np.int8)
        for cwe in self.cwes:
            X["cwe_" + cwe.split("-", 1)[1]] = (df["cwe"] == cwe).astype(np.int8)
        X["cwe_other"] = (~df["cwe"].isin(self.cwes)).astype(np.int8)
        for col in ("vendor", "product"):
            if oof:
                if not df.index.equals(self._train_index):
                    raise ValueError("oof=True requires the exact training frame used in fit()")
                X[f"{col}_kev_rate"] = self._oof[col].to_numpy()
            else:
                X[f"{col}_kev_rate"] = df[col].map(self.tables[col]).fillna(self.prior).astype(float)
        for c in REF_COLS:
            X[c] = df[c].astype(float)
        X["desc_len"] = df["desc_len"].astype(float)
        for c in KW_COLS:
            X[c] = df[c].astype(np.int8)
        extra = extra if extra is not None else pd.DataFrame(index=df.index)
        for c in (*POC_COLS, *include):  # fixed order -> stable feature vector
            if c not in extra.columns:
                raise ValueError(f"column '{c}' missing from `extra`")
            X[c] = extra[c].to_numpy()
        return X

    # -- persistence -----------------------------------------------------
    def to_json(self) -> dict:
        return {"cwes": self.cwes, "prior": self.prior, "smoothing": self.m, "tables": self.tables}

    @classmethod
    def from_json(cls, d: dict) -> "FeatureEncoder":
        enc = cls(smoothing=d["smoothing"])
        enc.cwes, enc.prior, enc.tables = d["cwes"], d["prior"], d["tables"]
        return enc

    def save(self, path) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_json(), f)
