#!/usr/bin/env bash
# End-to-end run on the SYNTHETIC test fixture (no network needed).
# Every artifact it writes is stamped data_source="synthetic-test-fixture" and
# the dashboard shows a red banner. For real results run scripts/run_pipeline.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf data/synthetic_raw
python -m tests.synthetic data/synthetic_raw
touch data/synthetic_raw/SYNTHETIC
python -m train.build_features --raw-dir data/synthetic_raw --years 2013-2026 --out data/features.parquet
python -m train.train --features data/features.parquet --out models/
python -m train.export --features data/features.parquet --models models/ --site site/
python -m backtest.run_backtest --features data/features.parquet --freeze 2025-01-01 --out site/backtest.json
python -c "import json;m=json.load(open('site/model_meta.json'));print('test AUC', round(m['test_auc'],3), '| data:', m['data_source'])"
python -m scripts.make_results_md
