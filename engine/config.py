"""Single source of truth for every constant the pipeline, backtest, API and
dashboard share. The dashboard mirrors the FORMULA block in site/engine.js; the
parity test (tests/test_parity.py) fails if the two ever drift apart."""
from __future__ import annotations

import datetime as _dt
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
MODELS_DIR = ROOT / "models"
SITE_DIR = ROOT / "site"
RESULTS_DIR = ROOT / "backtest" / "results"
FIGURES_DIR = ROOT / "docs" / "figures"

# --------------------------------------------------------------------------
# Public data sources (no API keys needed)
# --------------------------------------------------------------------------
NVD_URL = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-{year}.json.xz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MIRROR_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
EPSS_CURRENT_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
EPSS_DATED_URL = "https://epss.cyentia.com/epss_scores-{date}.csv.gz"
POC_GITHUB_REPO = "https://github.com/nomi-sec/PoC-in-GitHub.git"
EXPLOITDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

# --------------------------------------------------------------------------
# Time-based split (never random: a random split leaks future information)
# Split is on the NVD *published* date, not the CVE-ID year.
# --------------------------------------------------------------------------
TRAIN_YEARS = (2019, 2023)       # inclusive
VAL_YEAR = 2024
TEST_YEAR = 2025
FIRST_SCORE_YEAR = 1999          # CVE-ID years scored for the dashboard shards

# Backtest freeze date T: everything a ranker sees must be knowable at T.
FREEZE_DATE = _dt.date(2025, 1, 1)

# A public PoC counts as a feature only if it appeared within this many days
# of publication. This keeps the feature identical at training and scoring
# time and stops "a PoC was written after it hit KEV" from leaking the label.
POC_WINDOW_DAYS = 30

# Regression gate used by CI before a nightly model is published.
MIN_TEST_AUC = 0.80

# --------------------------------------------------------------------------
# Feature engineering
# --------------------------------------------------------------------------
TOP_CWES = 30
TARGET_ENCODING_SMOOTHING = 20.0   # m in (sum + m*prior) / (n + m)
N_FOLDS = 5
RANDOM_STATE = 42

KEYWORDS = {
    "kw_rce": r"remote code execution|execute arbitrary (?:code|commands)|arbitrary code execution|code injection|command injection",
    "kw_unauth": r"unauthenticated|without authentication|without requiring authentication|pre-auth|no authentication",
    "kw_deser": r"deseriali[sz]",
    "kw_ssrf": r"server-side request forgery|\bssrf\b",
    "kw_auth_bypass": r"authentication bypass|bypass(?:es|ing)? (?:the )?authentication|auth bypass",
}

EXPLOIT_DOMAINS = {
    "dom_exploitdb": ("exploit-db.com",),
    "dom_github": ("github.com", "gist.github.com"),
    "dom_packetstorm": ("packetstormsecurity.com", "packetstormsecurity.org", "packetstorm.news"),
    "dom_zdi": ("zerodayinitiative.com",),
}

# References that exist *because* a CVE is exploited are label leakage.
LEAKY_REFERENCE_MARKERS = (
    "cisa.gov/known-exploited-vulnerabilities",
    "cisa.gov/kev",
)

# --------------------------------------------------------------------------
# Scoring formulas. Keep in sync with site/engine.js (enforced by tests).
# --------------------------------------------------------------------------
FORMULA = {
    # Formula + ML  (implementation guide, "Scoring formula, restated")
    "ml": {
        "w_model": 0.5,
        "w_epss": 0.3,
        "w_kev": 0.2,
        "w_cvss_impact": 0.5,
        "w_fanin": 0.5,
        "cvss_impact_max": 6.0,          # CVSS v3 impact sub-score maxes at 6.0
        "scope_changed_mult": 1.15,
        "tier_mult": {"1": 1.5, "2": 1.25, "3": 1.0},
        "internet_facing_mult": 1.2,
        "handles_pii_mult": 1.0,         # guide specifies no PII weight; kept neutral
        "default_tier": 2,               # asset context present but service unmatched
    },
    # Formula (legacy)  -- the Cap-1 dashboard formula, reproduced exactly
    "legacy": {
        "w_epss": 0.65,
        "w_maturity": 0.35,
        "maturity": {"none": 0.05, "poc": 0.5, "weaponized": 0.9, "kev": 1.0},
        "w_cvss_impact": 0.5,
        "w_blast": 0.5,
        "cvss_impact_max": 6.0,
        "criticality_weight": {"Critical": 1.0, "High": 0.7, "Medium": 0.4, "Low": 0.2},
        "tier_to_criticality": {"1": "Critical", "2": "High", "3": "Medium"},
        "business_divisor": 3.0,
        "fanin_divisor": 5.0,
        "business_share": 0.75,
        "scope_changed_mult": 1.15,
        "trust_boundary_mult": 1.08,
    },
    "soft_ceiling_start": 90.0,
    "tiers": {"Critical": 75.0, "High": 50.0, "Medium": 25.0},
}


def today() -> _dt.date:
    return _dt.date.today()


def release_stamp() -> str:
    """Git tag / commit the artifacts were built from, so the dashboard, the
    report and the deck can all quote the same snapshot. "unknown" outside a
    checkout."""
    import subprocess
    try:
        out = subprocess.run(["git", "describe", "--tags", "--always", "--dirty"], cwd=ROOT,
                             capture_output=True, text=True, timeout=10)
        return out.stdout.strip() or "unknown"
    except Exception:  # noqa: BLE001 - git may be absent; never fail a build over this
        return "unknown"
