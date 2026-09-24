# Results

Model: `lightgbm`, trained 2026-09-23; data source `public-feeds`; KEV catalogue 2026.09.23; EPSS scores of 2026-09-23.

Split by NVD published date: train 108,024 CVEs (784 KEV), validate 39,944 (160), test 47,969 (197, 0.41%).

## Table 1 — Classifier vs baselines, 2025 test year (n=47,969, k=197 in KEV)

| Ranker | AUC-ROC | PR-AUC | Precision@100 | Precision@500 | Recall@1000 | Effort to cover 90% |
| --- | --- | --- | --- | --- | --- | --- |
| CVSS base score | 0.765 | 0.017 | 0.086 | 0.038 | 0.125 | 60.0% |
| EPSS (FIRST) | 0.972 | 0.464 | 0.690 | 0.230 | 0.665 | 5.0% |
| Our model, without EPSS | 0.917 | 0.221 | 0.410 | 0.154 | 0.508 | 25.2% |
| Our model, with EPSS | 0.982 | 0.544 | 0.730 | 0.284 | 0.802 | 3.9% |
| Logistic regression (explainability baseline) | 0.920 | 0.128 | 0.260 | 0.094 | 0.442 | 20.7% |
| Our model + time features (diagnostic) | 0.890 | 0.078 | 0.250 | 0.092 | 0.339 | 37.0% |

EPSS rows use the current EPSS file (already informed by post-publication exploitation): an optimistic upper bound. Metrics are expected values under random tie-breaking.

![Feature importance](figures/feature_importance.png)

## Table 2 — Backtest, frozen 2024-01-01

Answer key: CISA KEV rows with dateAdded > 2024-01-01. Frozen model `hist_gradient_boosting` trained on 2019-2022 with labels as of the freeze date (553 positives), 5-fold cross-fitted.

### acme: acme-commerce-platform — N=14 findings, M=0 later-exploited, 5 already in KEV

| Ranking method | Mean rank of later-exploited | Precision@10 | Precision@25 | Effort to cover 90% |
| --- | --- | --- | --- | --- |
| CVSS-only | n/a | 0.000 | 0.000 | n/a |
| Formula (Cap-1 dashboard) | n/a | 0.000 | 0.000 | n/a |
| Formula + ML | n/a | 0.000 | 0.000 | n/a |
| EPSS-only (reference) | n/a | 0.000 | 0.000 | n/a |
| ML probability only (diagnostic) | n/a | 0.000 | 0.000 | n/a |

Open findings only (5 already-in-KEV findings removed, N=9):

| Ranking method | Mean rank of later-exploited | Precision@10 | Precision@25 | Effort to cover 90% |
| --- | --- | --- | --- | --- |
| CVSS-only | n/a | 0.000 | 0.000 | n/a |
| Formula (Cap-1 dashboard) | n/a | 0.000 | 0.000 | n/a |
| Formula + ML | n/a | 0.000 | 0.000 | n/a |
| EPSS-only (reference) | n/a | 0.000 | 0.000 | n/a |
| ML probability only (diagnostic) | n/a | 0.000 | 0.000 | n/a |

![coverage acme](figures/coverage_backtest_acme.png)

### kev-app: kev-app — N=150 findings, M=4 later-exploited, 1 already in KEV

| Ranking method | Mean rank of later-exploited | Precision@10 | Precision@25 | Effort to cover 90% |
| --- | --- | --- | --- | --- |
| CVSS-only | 30.6 | 0.200 | 0.080 | 47.7% |
| Formula (Cap-1 dashboard) | 4.2 | 0.400 | 0.160 | 5.3% |
| Formula + ML | 6.8 | 0.300 | 0.160 | 11.3% |
| EPSS-only (reference) | 5.0 | 0.300 | 0.160 | 8.7% |
| ML probability only (diagnostic) | 23.5 | 0.300 | 0.120 | 58.7% |

Open findings only (1 already-in-KEV findings removed, N=149):

| Ranking method | Mean rank of later-exploited | Precision@10 | Precision@25 | Effort to cover 90% |
| --- | --- | --- | --- | --- |
| CVSS-only | 29.9 | 0.200 | 0.080 | 47.3% |
| Formula (Cap-1 dashboard) | 3.2 | 0.400 | 0.160 | 4.7% |
| Formula + ML | 5.8 | 0.300 | 0.160 | 10.7% |
| EPSS-only (reference) | 4.5 | 0.300 | 0.160 | 8.1% |
| ML probability only (diagnostic) | 23.2 | 0.300 | 0.120 | 58.4% |

Excluded (published after the freeze date): CVE-2023-49657, CVE-2024-23897, CVE-2024-24772, CVE-2024-24773, CVE-2024-24779, CVE-2024-26016, CVE-2024-27315, CVE-2024-28148, CVE-2024-34693, CVE-2024-39887, CVE-2024-43044, CVE-2024-43045, CVE-2024-47803, CVE-2024-47804, CVE-2024-53947, CVE-2024-53948, CVE-2024-53949, CVE-2024-55633, CVE-2025-27622, CVE-2025-27623, CVE-2025-27624, CVE-2025-27625, CVE-2025-27696, CVE-2025-31720, CVE-2025-31721, CVE-2025-48912, CVE-2025-55672, CVE-2025-55673, CVE-2025-55674, CVE-2025-55675, CVE-2025-59474, CVE-2025-59475, CVE-2025-59476, CVE-2025-67635, CVE-2025-67636, CVE-2025-67637, CVE-2025-67638, CVE-2025-67639, CVE-2026-23969, CVE-2026-23980, CVE-2026-23982, CVE-2026-23983, CVE-2026-23984, CVE-2026-27100, CVE-2026-33001, CVE-2026-53435, CVE-2026-53436, CVE-2026-53437, CVE-2026-53438, CVE-2026-53439, CVE-2026-53440, CVE-2026-53442

![coverage kev-app](figures/coverage_backtest_kev-app.png)

### legacy-java-app: struts2-showcase — N=36 findings, M=0 later-exploited, 9 already in KEV

| Ranking method | Mean rank of later-exploited | Precision@10 | Precision@25 | Effort to cover 90% |
| --- | --- | --- | --- | --- |
| CVSS-only | n/a | 0.000 | 0.000 | n/a |
| Formula (Cap-1 dashboard) | n/a | 0.000 | 0.000 | n/a |
| Formula + ML | n/a | 0.000 | 0.000 | n/a |
| EPSS-only (reference) | n/a | 0.000 | 0.000 | n/a |
| ML probability only (diagnostic) | n/a | 0.000 | 0.000 | n/a |

Open findings only (9 already-in-KEV findings removed, N=27):

| Ranking method | Mean rank of later-exploited | Precision@10 | Precision@25 | Effort to cover 90% |
| --- | --- | --- | --- | --- |
| CVSS-only | n/a | 0.000 | 0.000 | n/a |
| Formula (Cap-1 dashboard) | n/a | 0.000 | 0.000 | n/a |
| Formula + ML | n/a | 0.000 | 0.000 | n/a |
| EPSS-only (reference) | n/a | 0.000 | 0.000 | n/a |
| ML probability only (diagnostic) | n/a | 0.000 | 0.000 | n/a |

![coverage legacy-java-app](figures/coverage_backtest_legacy-java-app.png)

### population: all CVEs published before the freeze date — N=150,296 findings, M=121 later-exploited, 922 already in KEV

| Ranking method | Mean rank of later-exploited | Precision@10 | Precision@25 | Effort to cover 90% |
| --- | --- | --- | --- | --- |
| CVSS-only | 42149.3 | 0.003 | 0.003 | 53.1% |
| Formula (Cap-1 dashboard) | 23691.7 | 0.000 | 0.000 | 48.4% |
| Formula + ML | 20518.0 | 0.000 | 0.000 | 41.9% |
| EPSS-only (reference) | 38081.0 | 0.000 | 0.000 | 72.8% |
| ML probability only (diagnostic) | 26256.7 | 0.000 | 0.000 | 52.1% |

Open findings only (922 already-in-KEV findings removed, N=149,374):

| Ranking method | Mean rank of later-exploited | Precision@10 | Precision@25 | Effort to cover 90% |
| --- | --- | --- | --- | --- |
| CVSS-only | 41692.4 | 0.003 | 0.003 | 52.9% |
| Formula (Cap-1 dashboard) | 22929.7 | 0.000 | 0.160 | 48.1% |
| Formula + ML | 19673.2 | 0.000 | 0.120 | 41.5% |
| EPSS-only (reference) | 37474.7 | 0.100 | 0.120 | 72.6% |
| ML probability only (diagnostic) | 25639.1 | 0.000 | 0.000 | 51.9% |

Keeps only CVEs that EPSS scored on 2024-01-01; 2 unscored CVEs (0 later exploited) are excluded, because filling them with 0 would put them in one tied block at the bottom of the EPSS ranking.

![coverage population](figures/coverage_backtest_population.png)

## Table 3 — Ablation on Formula + ML (effort to cover 90%)

| Signal removed | acme | kev-app | legacy-java-app | population |
| --- | --- | --- | --- | --- |
| None (full Formula + ML) | n/a | 11.3% (+0.0 pp) | n/a | 41.9% (+0.0 pp) |
| ML probability | n/a | 8.7% (-2.7 pp) | n/a | 55.9% (+14.0 pp) |
| EPSS | n/a | 47.3% (+36.0 pp) | n/a | 51.6% (+9.8 pp) |
| KEV flag | n/a | 11.3% (+0.0 pp) | n/a | 41.9% (-0.0 pp) |
| Blast radius (fan-in) | n/a | 19.3% (+8.0 pp) | n/a | n/a |
| Scope multiplier | n/a | 11.3% (+0.0 pp) | n/a | 42.8% (+0.9 pp) |
| Asset criticality | n/a | 12.0% (+0.7 pp) | n/a | n/a |

A positive change means removing the signal made the ranking worse (more patching needed). A negative change means the signal hurt on this case and should be reported as such.

> The primary SBOM has fewer than 5 later-exploited CVEs; quote the population case for statistical claims.
