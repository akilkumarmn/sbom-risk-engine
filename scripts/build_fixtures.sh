#!/usr/bin/env bash
# Regenerate backtest/fixtures/legacy-java-app from a real public app with
# syft + trivy (the committed files are a hand-authored stand-in).
# Requires: git, maven (or a prebuilt war), syft >= 1.0, trivy >= 0.50.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=backtest/fixtures/legacy-java-app
WORK=$(mktemp -d)
# Struts 2.3.x builds with JDK 8 and Maven 3.
git clone --depth 1 --branch STRUTS_2_3_20 https://github.com/apache/struts.git "$WORK/struts"
( cd "$WORK/struts/apps/showcase" && mvn -q -DskipTests package )
WAR=$(ls "$WORK"/struts/apps/showcase/target/*.war | head -1)
syft "$WAR" -o cyclonedx-json > "$OUT/sbom.cdx.json"
# The freeze date matters: use a Trivy DB that is recent; the backtest drops
# every CVE published after the freeze date itself.
trivy sbom "$OUT/sbom.cdx.json" --format json --output "$OUT/trivy.json"
echo "wrote $OUT/sbom.cdx.json and $OUT/trivy.json -- review asset-context.json service mapping"
