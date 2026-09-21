#!/usr/bin/env bash
# Full run on the public feeds (same steps as .github/workflows/retrain.yml).
set -euo pipefail
cd "$(dirname "$0")/.."
YEARS="${YEARS:-2015-$(date +%Y)}"
FREEZE="${FREEZE:-2025-01-01}"
python -m train.fetch_data --years "$YEARS" --freeze "$FREEZE" --skip-existing
python -m train.build_features --years "$YEARS" --freeze "$FREEZE" --out data/features.parquet
python -m train.train --features data/features.parquet --out models/
python -m train.export --features data/features.parquet --models models/ --site site/
python -m backtest.run_backtest --features data/features.parquet --freeze "$FREEZE" --out site/backtest.json
python -m scripts.make_results_md
python -m scripts.gate
