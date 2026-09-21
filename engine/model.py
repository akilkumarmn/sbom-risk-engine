"""KEV exploitation classifier.

Primary learner: LightGBM (as specified in the implementation guide).
Fallback: scikit-learn HistGradientBoostingClassifier - the same histogram
gradient-boosting algorithm family - used only when lightgbm cannot be
imported (e.g. an offline sandbox). The learner actually used is recorded in
model_meta.json, so a result can never silently come from the fallback.

Probabilities: class weighting (is_unbalance) distorts probabilities, so the
raw margin is Platt-calibrated on the validation year. Calibration is
monotone, so rankings (AUC, PR-AUC, precision@k) are unaffected; it only makes
P_model a usable probability inside the risk formula."""
from __future__ import annotations

import json
import pickle
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from . import config

try:  # pragma: no cover - availability depends on the environment
    import lightgbm as lgb
    HAVE_LGBM = True
except Exception:  # noqa: BLE001
    lgb = None
    HAVE_LGBM = False


def _sigmoid(z):
    return 1.0 / (1.0 + np.exp(-np.clip(z, -35, 35)))


@dataclass
class TrainedModel:
    algo: str
    features: list[str]
    estimator: object
    platt_a: float = 1.0
    platt_b: float = 0.0
    best_iteration: int | None = None
    info: dict = field(default_factory=dict)

    # raw margin (log-odds before calibration)
    def margin(self, X: pd.DataFrame) -> np.ndarray:
        X = X[self.features]
        if self.algo == "lightgbm":
            return self.estimator.predict(X, raw_score=True, num_iteration=self.best_iteration)
        if self.algo == "hist_gradient_boosting":
            return self.estimator.decision_function(X)
        if self.algo == "logistic_regression":
            return self.estimator.decision_function(X)
        raise ValueError(self.algo)

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        return _sigmoid(self.platt_a * self.margin(X) + self.platt_b)

    def contributions(self, X: pd.DataFrame) -> np.ndarray | None:
        """Per-feature contributions to the raw margin, shape (n, n_features).
        LightGBM: exact TreeSHAP (pred_contrib). LogisticRegression: coef * z.
        HGB has no native attribution -> None (caller falls back to the LR)."""
        X = X[self.features]
        if self.algo == "lightgbm":
            c = self.estimator.predict(X, pred_contrib=True, num_iteration=self.best_iteration)
            return np.asarray(c)[:, :-1]  # last column is the bias
        if self.algo == "logistic_regression":
            scaler, lr = self.estimator.named_steps["standardscaler"], self.estimator.named_steps["logisticregression"]
            return scaler.transform(X) * lr.coef_[0]
        return None

    def importance(self, X_val: pd.DataFrame | None = None, y_val=None) -> dict[str, float]:
        if self.algo == "lightgbm":
            gain = self.estimator.booster_.feature_importance(importance_type="gain")
            return dict(zip(self.features, map(float, gain)))
        if self.algo == "logistic_regression":
            lr = self.estimator.named_steps["logisticregression"]
            return dict(zip(self.features, map(float, np.abs(lr.coef_[0]))))
        from sklearn.inspection import permutation_importance
        r = permutation_importance(self.estimator, X_val[self.features], y_val, scoring="average_precision",
                                   n_repeats=3, random_state=config.RANDOM_STATE)
        return dict(zip(self.features, map(float, r.importances_mean)))

    # -- persistence -----------------------------------------------------
    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(self, f)
        if self.algo == "lightgbm":  # portable, human-readable copy
            self.estimator.booster_.save_model(str(path.with_suffix(".txt")), num_iteration=self.best_iteration)

    @staticmethod
    def load(path: Path) -> "TrainedModel":
        with open(path, "rb") as f:
            return pickle.load(f)


def fit_gbm(X_tr: pd.DataFrame, y_tr, X_val: pd.DataFrame, y_val, algo: str = "auto") -> TrainedModel:
    y_tr = np.asarray(y_tr, dtype=int)
    y_val = np.asarray(y_val, dtype=int)
    features = list(X_tr.columns)
    if algo == "auto":
        algo = "lightgbm" if HAVE_LGBM else "hist_gradient_boosting"
    if algo == "lightgbm":
        if not HAVE_LGBM:
            raise RuntimeError("lightgbm requested but not installed (pip install lightgbm)")
        est = lgb.LGBMClassifier(
            n_estimators=600, learning_rate=0.03, num_leaves=31, min_child_samples=40,
            subsample=0.8, subsample_freq=1, colsample_bytree=0.8, reg_lambda=1.0,
            is_unbalance=True, metric="average_precision", random_state=config.RANDOM_STATE,
            n_jobs=-1, verbose=-1)
        # metric is set in the params so it is the ONLY monitored metric;
        # early stopping therefore tracks validation PR-AUC, not log-loss.
        est.fit(X_tr, y_tr, eval_set=[(X_val, y_val)],
                callbacks=[lgb.early_stopping(50, first_metric_only=True, verbose=False)])
        model = TrainedModel("lightgbm", features, est, best_iteration=est.best_iteration_ or None)
    elif algo == "hist_gradient_boosting":
        from sklearn.ensemble import HistGradientBoostingClassifier
        # Same regularisation intent as the LightGBM config; early stopping on
        # the explicit validation year is emulated by picking the best
        # iteration count on val average precision.
        best = None
        for n_iter in (150, 300, 600):
            est = HistGradientBoostingClassifier(
                max_iter=n_iter, learning_rate=0.05, max_leaf_nodes=31, min_samples_leaf=40,
                l2_regularization=1.0, class_weight="balanced", early_stopping=False,
                random_state=config.RANDOM_STATE)
            est.fit(X_tr, y_tr)
            ap = average_precision_score(y_val, est.decision_function(X_val)) if 0 < y_val.sum() < len(y_val) else 0
            if best is None or ap > best[0]:
                best = (ap, est, n_iter)
        model = TrainedModel("hist_gradient_boosting", features, best[1], best_iteration=best[2])
    else:
        raise ValueError(algo)
    calibrate(model, X_val, y_val)
    return model


def fit_logistic(X_tr: pd.DataFrame, y_tr, X_val: pd.DataFrame, y_val) -> TrainedModel:
    est = make_pipeline(StandardScaler(), LogisticRegression(class_weight="balanced", max_iter=5000, C=1.0))
    est.fit(X_tr, np.asarray(y_tr, dtype=int))
    model = TrainedModel("logistic_regression", list(X_tr.columns), est)
    calibrate(model, X_val, y_val)
    return model


def calibrate(model: TrainedModel, X_val: pd.DataFrame, y_val) -> None:
    """Platt scaling on the validation year: p = sigmoid(a * margin + b)."""
    y_val = np.asarray(y_val, dtype=int)
    if not (0 < y_val.sum() < len(y_val)):
        model.platt_a, model.platt_b = 1.0, 0.0
        return
    m = model.margin(X_val).reshape(-1, 1)
    lr = LogisticRegression(C=1e6, max_iter=1000)
    lr.fit(m, y_val)
    model.platt_a, model.platt_b = float(lr.coef_[0][0]), float(lr.intercept_[0])


def top_contributions(contrib: np.ndarray | None, features: list[str], k: int = 3) -> list[list[list]] | None:
    """Top-k features by |contribution| per row -> [[feature_index, value], ...]."""
    if contrib is None:
        return None
    idx = np.argsort(-np.abs(contrib), axis=1)[:, :k]
    rows = []
    for r, cols in enumerate(idx):
        rows.append([[int(c), round(float(contrib[r, c]), 3)] for c in cols if abs(contrib[r, c]) > 1e-9])
    return rows


def dump_json(obj, path: Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, default=_json_default)


def _json_default(o):
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return None if np.isnan(o) else float(o)
    if isinstance(o, (pd.Timestamp,)):
        return o.isoformat()
    if hasattr(o, "isoformat"):
        return o.isoformat()
    raise TypeError(type(o))
