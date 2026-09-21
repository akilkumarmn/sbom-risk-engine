# SBOM Context Risk Engine — AI-Based Vulnerability Prioritization using SBOM Context

Capstone Project 2 · Akil Kumar M N (R22MTC51) · M.Tech Cyber Security, REVA University (RACE), batch CS10

Ranks the vulnerabilities in an application by real-world risk instead of CVSS alone, combining:

- a **LightGBM classifier trained on NVD CVEs with CISA KEV as the label** (the project's AI component),
- live **EPSS** and **CISA KEV** threat intelligence, public PoC evidence,
- the **SBOM dependency graph** (fan-in / blast radius) and optional **asset context** (service tier, exposure),

and proves the ranking is better with a **time-frozen backtest** (freeze 1 Jan 2025, answer key = CVEs CISA
added to KEV afterwards).

> **Status of the numbers in this repo.** The committed artifacts (`site/model_meta.json`, `site/backtest.json`,
> `docs/results.md`, figures) were produced from the **synthetic offline test fixture** and are stamped
> `data_source: synthetic-test-fixture`; the dashboard shows a red banner for them. They show the pipeline works,
> not how well it performs. The first run of `scripts/run_pipeline.sh` or the nightly workflow on the public feeds
> replaces them with real results.

## Quick start

```bash
pip install -r train/requirements.txt          # Python 3.11+, plus Node 18+ for the parity tests
bash scripts/run_pipeline.sh                    # real data: fetch -> features -> train -> export -> backtest -> gate
python -m http.server -d site 8000              # dashboard at http://localhost:8000/dashboard.html
```

Offline (no network): `bash scripts/run_offline_demo.sh` runs the same pipeline on the synthetic fixture.
Tests: `python -m tests.run_tests` (unit, Python/JavaScript parity, leakage traps, backtest answer key).

| Step | Command | Output |
| --- | --- | --- |
| Fetch feeds | `python -m train.fetch_data --years 2015-2026` | `data/raw/` |
| Features | `python -m train.build_features --out data/features.parquet` | feature table + `features_meta.json` |
| Train (Table 1) | `python -m train.train` | `models/`, `train_report.json`, figures |
| Export | `python -m train.export` | `site/model_meta.json`, `site/data/cve/*.json`, `site/data/kev.json` |
| Backtest (Tables 2-3) | `python -m backtest.run_backtest --freeze 2025-01-01` | `backtest/results/`, `site/backtest.json`, figures |
| Write-up | `python -m scripts.make_results_md` | `docs/results.md` |
| Gate | `python -m scripts.gate` | fails unless test AUC > 0.80 on real data |
| Deck | `python -m scripts.build_deck --date "<viva date>" --url <pages URL>` | `docs/deck/Cap2_SBOM_Risk_Engine_results.pptx` |

## Dashboard (`site/dashboard.html`)
Runs entirely in the browser. Upload a CycloneDX SBOM, a scan (Trivy JSON, Nessus, CSV) and optionally
`asset-context.json`; toggle **CVSS-Only / Formula / Formula + ML** to watch the ranking move twice. Each finding
shows its formula breakdown, the model probability and its top three contributing features. EPSS and KEV are
fetched live (cached 24 h in localStorage) with a dated snapshot fallback. Only CVE IDs are sent to FIRST; the
SBOM and scan never leave the page. Deployed by `.github/workflows/pages.yml` to
`https://<github-user>.github.io/sbom-risk-engine/`.

## API (`api/`)
```bash
docker build -f api/Dockerfile -t sbom-risk-engine . && docker run -p 8080:8080 sbom-risk-engine
curl -F sbom=@backtest/fixtures/acme/sbom.cdx.json -F scan=@backtest/fixtures/acme/trivy.json \
     -F asset_context=@backtest/fixtures/acme/asset-context.json http://localhost:8080/score
```
Swagger UI at `http://localhost:8080/docs`. Same scoring code and exported model output as the dashboard.

## Repository layout
```
engine/      shared Python core: sources, features, model, metrics, CVSS, SBOM/scan ingestion, scoring, service
train/       fetch_data.py, build_features.py, train.py, export.py, requirements.txt
backtest/    run_backtest.py, fixtures/{acme,legacy-java-app}/ (SBOM + Trivy + asset context), results/
site/        dashboard.html, engine.js (browser mirror of engine/), model_meta.json, backtest.json, data/, samples/
api/         main.py (FastAPI), Dockerfile
notebooks/   01_eda, 02_model, 03_backtest
docs/        methodology.md, results.md (generated), limitations.md, figures/, deck/ (results deck + template)
tests/       synthetic fixture generator, unit / parity / pipeline tests, run_tests.py
scripts/     run_pipeline.sh, run_offline_demo.sh, build_fixtures.sh, gate.py, make_results_md.py, build_deck.py, screenshot_dashboard.py
.github/workflows/  retrain.yml (nightly), pages.yml, tests.yml
```

## Design decisions worth knowing
- **Time split, never random** (train 2019-2023 / validate 2024 / test 2025 by NVD published date).
- **No label leakage:** KEV-derived NVD fields and KEV-catalogue references are ignored; PoC evidence counts only
  within 30 days of publication; target encodings are fitted on training years with out-of-fold values.
- **Tie-aware metrics:** CVSS produces large blocks of identical scores; every metric is the exact expected value
  under random tie-breaking.
- **The backtest re-trains its own model** with labels as of the freeze date and cross-fits it, so no CVE is scored
  by a model that saw its outcome.
- **One formula, two languages:** `engine/scoring.py` and `site/engine.js` are checked for identical output by
  `tests/test_parity.py`.

See `docs/methodology.md`, `docs/results.md` and `docs/limitations.md`.
