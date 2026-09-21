"""Regression gate used by CI before a nightly model is published.
Fails (exit 1) if the published model is worse than config.MIN_TEST_AUC, if it
was trained on the synthetic fixture, or if the backtest is missing.

    python -m scripts.gate [--allow-synthetic]
"""
from __future__ import annotations

import argparse
import json
import sys

from engine import config


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--allow-synthetic", action="store_true")
    args = ap.parse_args(argv)
    meta = json.loads((config.SITE_DIR / "model_meta.json").read_text())
    bt_path = config.SITE_DIR / "backtest.json"
    problems = []
    if meta["test_auc"] is None or meta["test_auc"] <= config.MIN_TEST_AUC:
        problems.append(f"test AUC {meta['test_auc']} <= gate {config.MIN_TEST_AUC}")
    if meta.get("data_source") != "public-feeds" and not args.allow_synthetic:
        problems.append(f"model data_source is '{meta.get('data_source')}', not public-feeds")
    if not bt_path.exists():
        problems.append("site/backtest.json missing")
    if problems:
        print("GATE FAILED:\n  " + "\n  ".join(problems))
        return 1
    print(f"gate passed: test AUC {meta['test_auc']:.3f} > {config.MIN_TEST_AUC}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
