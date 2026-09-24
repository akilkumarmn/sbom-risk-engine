# Methodology

## 1. Problem
CVSS measures severity, not the likelihood of exploitation or the damage in *this* organisation. The engine ranks
the vulnerabilities in an application (SBOM + scanner output) by combining a learned exploitation probability,
public threat intelligence (EPSS, CISA KEV, public PoCs), the SBOM dependency graph and user-supplied business
context. The claim is tested against CVSS with a time-frozen backtest.

## 2. Data (all public, no API keys)
| Source | Use |
| --- | --- |
| NVD CVE feed, fkie-cad GitHub mirror (`CVE-YYYY.json.xz`) | CVSS v3 vector and base score (NVD Primary preferred), CWE, CPE vendor/product, references, published date |
| CISA KEV JSON (cisa.gov, GitHub mirror as fallback) | label; `dateAdded` reconstructs KEV as of any past date |
| FIRST EPSS, current and `epss_scores-2025-01-01.csv.gz` | baseline, model variant, backtest input |
| nomi-sec PoC-in-GitHub, Exploit-DB `files_exploits.csv` | first public-PoC dates |

Rejected CVE records are dropped. Fields that exist *because* a CVE is exploited are ignored: `cisaExploitAdd`,
`cisaActionDue`, `cisaRequiredAction`, CISA-ADP SSVC `exploitation`, and references pointing to the KEV catalogue.
`tests/test_pipeline.py` plants all of these in the synthetic fixture and asserts none reach the feature matrix.

## 3. Features (per CVE, knowable at publication)
CVSS v3 base score and one-hot vector (AV, AC, PR, UI, S, C, I, A; a missing-vector flag); top-30 CWE one-hot
plus "other"; vendor and product KEV rate, target-encoded on training years only with smoothing (m=20) and
out-of-fold values for training rows; reference counts (total, Exploit, Patch, Vendor Advisory) and domain
flags (exploit-db, github, packetstorm, ZDI); description length and keyword flags (code execution,
unauthenticated, deserialization, SSRF, authentication bypass); public PoC on GitHub / Exploit-DB **within 30
days of publication**. The 30-day window keeps the feature identical at training and scoring time and stops
"a PoC appeared after the CVE hit KEV" from leaking the label. EPSS is a feature only in the "with EPSS"
variant; days-since-publish and publication year only in a diagnostic variant (they encode label maturity).

## 4. Model
Label: CVE listed in CISA KEV. Split by NVD published date, never random: train 2019-2023, validate 2024,
test 2025. LightGBM (600 trees max, lr 0.03, 31 leaves, min_child_samples 40, subsample/colsample 0.8,
L2 1.0, `is_unbalance`), early stopping on validation PR-AUC. Where LightGBM is unavailable the code falls back to
scikit-learn's HistGradientBoosting (same algorithm family) and records which learner produced every artifact.
Class weighting distorts probabilities, so the margin is Platt-calibrated on the validation year; calibration
is monotone and does not change any ranking metric. A class-balanced logistic regression is trained on the same
features as the explainability baseline.

Metrics (Table 1): AUC-ROC, PR-AUC, Precision@100/@500, Recall@1000 and effort to cover 90% of KEV positives.
All ranking metrics are **expected values under random tie-breaking**: CVSS assigns identical scores to
thousands of CVEs, and file-order tie-breaking would make it look arbitrarily good or bad.

## 5. Deployment of the model to the browser
The guide suggests m2cgen. Scoring needs NVD fields (vector, CWE, CPE vendor, references, PoC dates) that a
scanner report does not contain, so the browser would have to download per-CVE feature vectors anyway. Instead
the nightly job scores every CVE and publishes `site/data/cve/<year>.json` shards (probability, EPSS, KEV, PoC
flags, CVSS impact/scope/base, top-3 feature contributions). The dashboard lazy-loads only the years present in
the uploaded scan. The SBOM and scan never leave the browser; with live intel on, only CVE IDs are sent to FIRST.

## 6. Risk formulas (identical in `engine/scoring.py` and `site/engine.js`, enforced by `tests/test_parity.py`)
**CVSS-only:** 10 × base.

**Formula (Cap-1 dashboard, reproduced exactly):** Likelihood = 0.65·EPSS + 0.35·Maturity (KEV 1.0,
Exploit-DB 0.9, GitHub PoC 0.5, none 0.05); Impact = 0.5·CVSSimpact/6 + 0.5·BlastRadius; ×1.15 scope changed,
×1.08 if the component crosses a trust boundary; soft ceiling above 90.

**Formula + ML (this phase's design):**
Risk = 100 · (0.5·P_model + 0.3·EPSS + 0.2·KEV) · ((0.5·CVSSimpact/6 + 0.5·fan-in/max fan-in) · Crit_asset) · (1.15 if scope changed).
Crit_asset = 1.5 / 1.25 / 1.0 for tier 1 / 2 / 3, ×1.2 if internet-facing; 1.0 with no asset context; tier 2
when context is supplied but the finding maps to no service. The guide writes CVSSimpact/10; the v3 impact
sub-score maxes out at 6.0, so /10 would cap the term at 0.6 — /6 normalises it to [0, 1].

Fan-in is the number of components that transitively depend on the vulnerable component (SBOM `dependencies`,
looked up by bom-ref). Services map to findings by component (`name@version`, purl or bom-ref), by top-level
component name (a bare name also matches every descendant), by service name in the dependency chain, or by
Nessus host.

## 7. Backtest (Tables 2 and 3)
Freeze date T = 2025-01-01. Inputs frozen at T: EPSS file of T, KEV rows with `dateAdded ≤ T`, PoC dates ≤ T,
and a model **re-trained for the backtest** with labels as of T (train 2019-2023, validate 2024). CVEs in the
training years are scored 5-fold cross-fitted with fold-specific target encoders, so no CVE is scored by a
model that saw it. Only CVEs published before T can appear in a scan taken at T. CVSS comes from today's NVD
feed (rarely re-scored; stated assumption). Answer key: KEV rows added after T.

Rankers: CVSS-only, Formula, Formula + ML, EPSS-only (reference) and model-only (diagnostic). Reported per case:
mean rank of the later-exploited CVEs, Precision@10/@25 and effort to cover 90%; CVEs already in KEV at T stay
in the list and are reported separately, with an open-findings-only variant. Cases: each SBOM fixture (fan-in and
asset context active) and the whole CVE population published before T (statistical power; SBOM terms are 0).
Ablation zeroes one Formula + ML signal at a time (model, EPSS, KEV, fan-in, scope, asset criticality).

## 8. MLOps
`retrain.yml` (nightly 03:00 IST): fetch feeds → features → train → export → backtest → results.md → tests →
gate (test AUC > 0.80 on real data) → commit artifacts → deploy GitHub Pages. `tests.yml` runs the unit, parity
and leakage tests on every push using the synthetic fixture. `api/` serves the same scoring over REST.


## Population case and EPSS coverage (updated)

EPSS does not publish a score for every CVE. Earlier runs filled the gaps with 0.0, which placed every unscored
CVE in one tied block at the bottom of the EPSS ranking and made the EPSS baseline look close to random. The
population case now keeps only CVEs that EPSS scored on the freeze date and reports how many were excluded; the
unrestricted numbers stay in `backtest.json` under `all_cves_variant`.

## Backtest fixtures with later-exploited CVEs

A backtest case can only measure something if some of its CVEs were added to KEV after the freeze date. The
`kev-2025-app` fixture is built for that: `scripts/make_backtest_fixture.py` selects the CVEs published before the
freeze date that CISA added afterwards, asks OSV which package versions they affect, and writes Maven, npm and
PyPI manifests pinned to those versions. Syft and Trivy then produce the SBOM and the scan
(`scripts/build_kev_fixture.sh`), so the fixture is real scanner output; `--verify` reports how many of the target
CVEs Trivy actually detects.
