#!/usr/bin/env bash
# Turn the generated manifests into a real SBOM + scan with Syft and Trivy.
#
#   python -m scripts.make_backtest_fixture --freeze 2025-01-01   # writes src/
#   bash scripts/build_kev_fixture.sh
#   python -m scripts.make_backtest_fixture --verify
#
# Needs syft and trivy on PATH, or Docker (set USE_DOCKER=1).
set -euo pipefail
cd "$(dirname "$0")/.."
FIX="backtest/fixtures/kev-2025-app"
[ -d "$FIX/src" ] || { echo "run 'python -m scripts.make_backtest_fixture' first"; exit 1; }

if [ "${USE_DOCKER:-0}" = "1" ]; then
  SYFT="docker run --rm -v $PWD/$FIX:/w anchore/syft:latest"
  TRIVY="docker run --rm -v $PWD/$FIX:/w aquasec/trivy:latest"
  $SYFT dir:/w/src -o cyclonedx-json > "$FIX/sbom.cdx.json"
  $TRIVY sbom /w/sbom.cdx.json --format json --output /w/trivy.json
else
  syft "dir:$FIX/src" -o cyclonedx-json > "$FIX/sbom.cdx.json"
  trivy sbom "$FIX/sbom.cdx.json" --format json --output "$FIX/trivy.json"
fi

python -c "
import json,sys
sb=json.load(open('$FIX/sbom.cdx.json')); sc=json.load(open('$FIX/trivy.json'))
n=len(sb.get('components',[])); v=sum(len(r.get('Vulnerabilities') or []) for r in sc.get('Results',[]))
print(f'SBOM: {n} components | scan: {v} findings')
sys.exit(0 if n and v else 1)"
echo "now: python -m scripts.make_backtest_fixture --verify"
echo "then: python -m backtest.run_backtest --features data/features.parquet --freeze 2025-01-01 --out site/backtest.json --primary kev-2025-app"
