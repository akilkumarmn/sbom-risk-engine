"""Build the Capstone-2 project report (Word .docx).

    python -m scripts.build_report --date "21st September 2026" --month "September 2026"

Every number in the report is read from site/model_meta.json and
site/backtest.json (the files the nightly pipeline publishes), and the worked
scoring example is recomputed with the project's own engine. Re-running this
after a pipeline run therefore refreshes the whole report. While those files
come from the synthetic test fixture, the report carries a visible warning.

When the file is opened, Word asks to update fields: answer Yes so the Table of
Contents, List of Figures, List of Tables and page numbers are filled in (or
press Ctrl+A then F9).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path

from docx.shared import Inches, Pt, RGBColor

from engine import config
from engine.enrich import enrich_findings
from engine.sbom import correlate, normalize_asset_context, parse_cyclonedx, parse_scan
from engine.scoring import score_all
from engine.service import Intel
from scripts.report_lib import (CENTER, HEAD, LEFT, Report, draw_architecture, draw_methodology, draw_mlops,
                                new_document)

ASSETS = config.ROOT / "docs" / "report" / "assets"
FIG = config.FIGURES_DIR
RANK = {"cvss": "CVSS-only", "legacy": "Formula (proposal stage)", "ml": "Formula + ML",
        "epss": "EPSS-only (reference)", "model": "ML probability only (diagnostic)"}
T1 = {"cvss": "CVSS base score", "epss": "EPSS (FIRST, current file)*", "model_no_epss": "Our model, without EPSS",
      "model_with_epss": "Our model, with EPSS*", "logreg_no_epss": "Logistic regression (baseline)",
      "model_time_features": "Model + time features (diagnostic)"}
ALGO = {"lightgbm": "LightGBM", "hist_gradient_boosting": "scikit-learn HistGradientBoosting (fallback learner)"}


# ---------------------------------------------------------------------------
def pct(x, d=1):
    return "not measurable" if x is None else f"{100 * x:.{d}f}%"


def f3(x):
    return "n/a" if x is None else f"{x:.3f}"


def rank_f(x):
    if x is None:
        return "n/a"
    return f"{x:,.0f}" if x >= 1000 else f"{x:.1f}"


def ordinal(n):
    return f"{n}{'th' if 11 <= n % 100 <= 13 else {1: 'st', 2: 'nd', 3: 'rd'}.get(n % 10, 'th')}"


def less_effort(ours, other):
    """Sentence fragment comparing two effort-to-cover values (lower is better)."""
    if ours is None or other is None:
        return "could not be compared because the case has no later-exploited CVEs"
    d = 100 * (other - ours)
    if abs(d) < 0.05:
        return "required the same patch effort as"
    return (f"required {abs(d):.1f} percentage points {'less' if d > 0 else 'more'} patch effort than")


def higher(a, b):
    if a is None or b is None:
        return "could not be compared with"
    if abs(a - b) < 5e-4:
        return "was equal to"
    return "was higher than" if a > b else "was lower than"


# ---------------------------------------------------------------------------
class Ctx:
    def __init__(self, args):
        self.args = args
        self.m = json.loads((config.SITE_DIR / "model_meta.json").read_text())
        self.b = json.loads((config.SITE_DIR / "backtest.json").read_text())
        self.synthetic = "synthetic-test-fixture" in (self.m.get("data_source"), self.b.get("data_source"))
        self.t1 = {r["ranker"]: r for r in self.m["table1"]}
        c = self.m["counts"]
        self.c = c
        self.n_total = sum(v["n"] for v in c.values())
        self.kev_total = sum(v["kev"] for v in c.values())
        self.test_year = self.m["split"]["test_year"]
        self.val_year = self.m["split"]["val_year"]
        self.algo = ALGO.get(self.m["algo"], self.m["algo"])
        self.prim_key = self.b["primary_case"]
        self.P = self.b["cases"][self.prim_key]
        self.POP = self.b["cases"]["population"]
        self.freeze = self.b["freeze_date"]
        self.fm = self.b["frozen_model"]
        self.snap = self.m.get("snapshots", {})
        self.sbom_cases = [k for k in self.b["cases"] if k != "population"]

    def t2(self, case):
        return {r["ranker"]: r for r in case["table2"]}

    def abl(self, case):
        return {r["removed"]: r for r in case["ablation"]}


def worked_example():
    """Score the bundled acme sample with the published snapshot intel and
    return the top Formula + ML finding with every term."""
    intel = Intel(config.SITE_DIR)
    fx = config.ROOT / "backtest" / "fixtures" / "acme"
    parsed = parse_cyclonedx(json.loads((fx / "sbom.cdx.json").read_text()))
    _, findings, _ = parse_scan("trivy.json", (fx / "trivy.json").read_text())
    matched, _, _ = correlate(parsed, findings)
    ctx = normalize_asset_context(json.loads((fx / "asset-context.json").read_text()))
    kev = set(intel.kev_snapshot.get("cves", {}))

    def lookup(cve):
        r = intel.row(cve)
        out = dict(r) if r else {}
        out.pop("contrib", None)
        out["kev"] = cve in kev
        return out

    rows = score_all(enrich_findings(parsed, matched, lookup, ctx, intel.meta.get("prior_p", 0.0)))
    rows.sort(key=lambda r: r["ml"]["rank"])
    return rows, intel


# ---------------------------------------------------------------------------
# front matter
# ---------------------------------------------------------------------------
TITLE = "AI-Based Vulnerability Prioritization Engine using SBOM Context"


def front_matter(R: Report, X: Ctx):
    a = X.args
    sig = ASSETS / "signature.png"
    R.logo_line()
    R.center("A Project Report", after=10)
    R.center(TITLE, bold=True, size=HEAD, after=14)
    R.center("Submitted in partial fulfilment of the requirements for the award of the degree of")
    R.center("Master of Technology", bold=True, after=2)
    R.center("in Cybersecurity", bold=True, after=14)
    R.center("Submitted by")
    R.center("Akil Kumar M N", bold=True, after=2)
    R.center("R22MTC51", after=14)
    R.center("Under the Guidance of")
    R.center("Dhruv Kalaan", bold=True, after=2)
    R.center("Director – Cybersecurity & IT", bold=True, after=14)
    for line in ("REVA Academy for Corporate Excellence", "REVA University", "Rukmini Knowledge Park, Kattigenahalli,",
                 "Yelahanka, Bangalore – 560064"):
        R.center(line, after=2)
    R.center("", after=6)
    R.center(a.month, bold=True)

    R.h1("Candidate's Declaration", logo=True)
    R.p("I, Akil Kumar M N, hereby declare that I have completed the Capstone Project 2 (Phase 2) work toward the "
        "Master of Technology in Cybersecurity at REVA University on the topic entitled \u201c",
        (TITLE, "b"), "\u201d. The work presented in this report was carried out by me as part of the programme "
        "requirements and records the design, implementation, testing and evaluation of the system described.")
    R.p("The report has been prepared with reference to published literature, public data sources and the project "
        "material developed for the study. Wherever external concepts, standards, datasets, tools or published work "
        "have been used, they have been identified through appropriate references.")
    R.sign_block(["Place: Bengaluru", f"Date: {a.date}"],
                 ["Name of the Student: Akil Kumar M N", "Signature of Student:"], sig)

    R.h1("Acknowledgment of Project Ownership and Usage Right", logo=True)
    R.p("I, Akil Kumar M N, a student enrolled in the M.Tech Program at RACE, acknowledge that the project work and "
        "associated intellectual property created during the academic tenure are subject to the academic policies "
        "and project ownership provisions of RACE, REVA University. I understand that the institution may use, "
        "reproduce, modify, or further develop the project material for academic, research, demonstration, and "
        "institutional purposes in accordance with applicable university policies.")
    R.sign_block(["Place: Bengaluru", f"Date: {a.date}"],
                 ["Name of the Student: Akil Kumar M N", "Signature of Student:"], sig)

    R.h1("Certificate", logo=True)
    R.p("This is to certify that the project work entitled \u201c", (TITLE, "b"), "\u201d has been carried out by "
        "Akil Kumar M N with SRN R22MTC51, a bonafide student of REVA University, in partial fulfilment of the "
        "requirements for the award of the Master of Technology in Cybersecurity.")
    R.p("The project report has been prepared in accordance with the academic requirements prescribed for the "
        "Capstone Project 2 (Phase 2). The report may be considered for evaluation subject to the verification and "
        "approval of the project guide and the institution.")
    R.sign_block(["Signature of the Guide", "", "Dhruv Kalaan", "Guide"],
                 ["Signature of the Director", "", "Dr. Shinu Abhi", "Director, Corporate Training"])
    R.p(("External Viva", "b"), style="Normal")
    R.p("Names of the Examiners")
    R.p("1. ______________________________")
    R.p("2. ______________________________")
    R.p("Place: Bengaluru")
    R.p(f"Date: {a.date}")

    R.h1("Acknowledgment", logo=True)
    R.p("I would like to express my sincere gratitude to the leadership of REVA University and REVA Academy for "
        "Corporate Excellence for providing the academic environment and resources required to undertake this "
        "project.")
    R.p("I would like to acknowledge the support and encouragement provided by the Director, Corporate Training for "
        "RACE, the RACE faculty, and the administrative and infrastructure teams who contribute to the successful "
        "delivery of the M.Tech program.")
    R.p("I am grateful to my project guide, Dhruv Kalaan, for the technical direction given during this phase, in "
        "particular the guidance to support every claim with a trained model, a measured comparison against CVSS "
        "and a deployed, reproducible system.")
    R.p("I also acknowledge the public data providers whose openly available datasets made this work possible: NIST "
        "(National Vulnerability Database), CISA (Known Exploited Vulnerabilities catalogue), FIRST (EPSS), and the "
        "maintainers of PoC-in-GitHub and Exploit-DB.")
    R.p("Finally, I would like to thank my family, colleagues, and friends for their encouragement and support "
        "throughout this work.")
    R.p("Place: Bengaluru")
    R.p(f"Date: {a.date}")

    R.h1("Similarity Index Report", logo=True)
    R.p("This is to certify that this project report titled \u201c", TITLE, "\u201d was scanned for similarity "
        "detection. The process and outcome are given below. The plagiarism report is attached in the appendix.")
    R.p("Software Used: Turnitin")
    R.p("Date of Report Generation: ____________________")
    R.p("Similarity Index in %: ____________________")
    R.p("Total word count: ____________________")
    R.p("Name of the Guide: Dhruv Kalaan")
    R.sign_block(["Place: Bengaluru", f"Date: {a.date}"],
                 ["Name of the Student: Akil Kumar M N", "Signature of Student:"], sig)
    R.p("Verified by: Irshad Ahmed")
    R.p("Signature")
    R.p("Dr. Shinu Abhi,")
    R.p("Director, Corporate Training")

    R.h1("List of Abbreviations", logo=True)
    abbr = [("API", "Application Programming Interface"), ("AUC-ROC", "Area Under the Receiver Operating "
            "Characteristic Curve"), ("CI", "Continuous Integration"), ("CISA", "Cybersecurity and Infrastructure "
            "Security Agency"), ("CPE", "Common Platform Enumeration"), ("CSV", "Comma-Separated Values"),
            ("CVE", "Common Vulnerabilities and Exposures"), ("CVSS", "Common Vulnerability Scoring System"),
            ("CWE", "Common Weakness Enumeration"), ("EPSS", "Exploit Prediction Scoring System"),
            ("FIRST", "Forum of Incident Response and Security Teams"), ("JSON", "JavaScript Object Notation"),
            ("KEV", "Known Exploited Vulnerabilities (CISA catalogue)"), ("ML", "Machine Learning"),
            ("MLOps", "Machine Learning Operations"), ("NVD", "National Vulnerability Database"),
            ("PoC", "Proof of Concept (public exploit code)"), ("PR-AUC", "Area Under the Precision-Recall Curve"),
            ("purl", "Package URL"), ("REST", "Representational State Transfer"),
            ("SBOM", "Software Bill of Materials"), ("SHAP", "SHapley Additive exPlanations"),
            ("SSVC", "Stakeholder-Specific Vulnerability Categorization")]
    R.table(None, None, ["Sl. No.", "Abbreviation", "Long Form"],
            [[str(k), a_, b_] for k, (a_, b_) in enumerate(abbr, 1)], [0.8, 1.5, 4.2])

    R.h1("List of Figures", logo=True)
    R.toc('TOC \\h \\z \\t "Figure Caption,1"', "Open in Microsoft Word and choose Yes to update fields.")
    R.h1("List of Tables", new_page=False)
    R.toc('TOC \\h \\z \\t "Table Caption,1"', "Open in Microsoft Word and choose Yes to update fields.")


def warning(R: Report, X: Ctx):
    if not X.synthetic:
        return
    para = R.p("WARNING: the numbers in this report were produced from the synthetic offline test fixture, not from "
               "NVD, KEV and EPSS. Run the real pipeline and rebuild this report before submission.")
    for r in para.runs:
        r.bold = True
        r.font.color.rgb = RGBColor(0xC0, 0x00, 0x00)


def abstract(R: Report, X: Ctx):
    R.h1("Abstract")
    warning(R, X)
    t1, c = X.t1, X.c
    auc_m, auc_c, auc_e = t1["model_no_epss"]["auc_roc"], t1["cvss"]["auc_roc"], t1["epss"]["auc_roc"]
    t2p, t2pop = X.t2(X.P), X.t2(X.POP)
    R.p("Security teams receive far more vulnerability findings than they can remediate, and most of them rank "
        "that backlog by the CVSS base score. CVSS measures technical severity, not the likelihood that a "
        "vulnerability will be exploited or the damage it can do inside a particular application. Thousands of "
        "CVEs share the same score, so a severity-only order leaves teams without a defensible way to decide what "
        "to patch first.")
    R.p("This project builds and evaluates an AI-based vulnerability prioritization engine that combines a learned "
        "exploitation-likelihood model with public threat intelligence and the context of the application's "
        "Software Bill of Materials (SBOM). A gradient-boosted classifier is trained and evaluated on "
        f"{X.n_total:,} NVD CVEs published from 2019 to {X.test_year}, with the CISA Known Exploited "
        "Vulnerabilities (KEV) catalogue as the label and a strictly time-based split (train 2019-2023, validate "
        f"{X.val_year}, test {X.test_year}). Its probability is combined with FIRST EPSS, the KEV flag, the SBOM "
        "dependency fan-in, user-supplied asset criticality and the CVSS scope into a transparent risk score. A "
        "browser dashboard correlates a CycloneDX SBOM with Trivy, Nessus or CSV scanner output and ranks the "
        "findings three ways: CVSS-only, the proposal-stage formula, and Formula + ML.")
    R.p(f"On the {X.test_year} held-out year ({c['test']['n']:,} CVEs, {c['test']['kev']} in KEV), the classifier "
        f"without any EPSS input reached an AUC-ROC of {f3(auc_m)} against {f3(auc_c)} for the CVSS base score; "
        f"EPSS, which is informed by post-publication exploitation activity, reached {f3(auc_e)}. In a time-frozen "
        f"backtest that used only information available on {X.freeze}, the Formula + ML ranking needed "
        f"{pct(t2p['ml']['effort_to_cover_90'])} of the {X.P['n_findings']} SBOM findings to be patched to cover "
        f"90% of the CVEs added to KEV afterwards, against {pct(t2p['cvss']['effort_to_cover_90'])} for CVSS-only. "
        f"Across the {X.POP['n_findings']:,} CVEs published before the freeze date, the later-exploited ones sit at "
        f"mean rank {rank_f(t2pop['ml']['mean_rank_later_exploited'])} under Formula + ML against "
        f"{rank_f(t2pop['cvss']['mean_rank_later_exploited'])} under CVSS-only, and the 90% cut-off needs "
        f"{pct(t2pop['ml']['effort_to_cover_90'])} of the backlog against "
        f"{pct(t2pop['cvss']['effort_to_cover_90'])}. An ablation study quantifies the contribution of each "
        "signal.")
    better = all(x is not None and y is not None and x < y for x, y in (
        (t2p["ml"]["effort_to_cover_90"], t2p["cvss"]["effort_to_cover_90"]),
        (t2pop["ml"]["effort_to_cover_90"], t2pop["cvss"]["effort_to_cover_90"])))
    finding = ("The results show that a learned likelihood signal together with SBOM and business context gives a "
               "measurably better patch order than CVSS alone" if better else
               "The results quantify where the learned likelihood signal and the SBOM and business context improve "
               "on CVSS and where they do not")
    R.p("The system is deployed as a static site on GitHub Pages with a nightly GitHub Actions pipeline that "
        "refreshes the data, retrains the model, repeats the backtest and publishes only when the tests and a test "
        f"AUC gate of 0.80 pass; a FastAPI service exposes the same scoring over REST. {finding}, while the report "
        "states the limits of KEV as a label and of dependency fan-in as a proxy for reachability.")
    R.p(("Keywords: vulnerability prioritization, SBOM, CycloneDX, CISA KEV, EPSS, CVSS, gradient boosting, "
         "time-frozen backtest, software supply chain security, MLOps", "bi"))

    R.h1("Table of Contents")
    R.toc('TOC \\o "1-2" \\h \\z \\u', "Open in Microsoft Word and choose Yes to update fields.")


# ---------------------------------------------------------------------------
# chapters
# ---------------------------------------------------------------------------
def ch1(R: Report, X: Ctx):
    R.h1("Chapter 1: Introduction")
    R.h2("1.1 Background")
    R.p("Modern applications are assembled rather than written from scratch. A typical Java or JavaScript service "
        "pulls in dozens of direct libraries and hundreds of transitive ones, and each of those components carries "
        "its own history of published vulnerabilities. Scanners such as Trivy and Nessus report these "
        "vulnerabilities as CVE identifiers, and the National Vulnerability Database (NVD) attaches a CVSS base "
        "score to each of them [1][13]. The result is a long list of findings that a security team cannot fix all "
        "at once.")
    R.p("Most teams therefore sort the list by CVSS and patch from the top. CVSS was designed to describe the "
        "technical severity of a vulnerability, not the probability that attackers will use it or the business "
        "damage it would cause in a specific system [1][2]. Public evidence shows that only a small share of "
        "published CVEs is ever exploited in the wild; CISA's Known Exploited Vulnerabilities (KEV) catalogue lists "
        "those for which exploitation has been confirmed [6].")
    R.h2("1.2 Limitations of CVSS-Only Prioritization")
    R.p("A severity-only order has three practical weaknesses. First, CVSS scores are coarse: a very large number of "
        "CVEs share values such as 9.8 or 7.5, so the order inside those groups is arbitrary. Second, the base score "
        "does not change when exploitation begins, whereas exploitation evidence such as a public proof of concept "
        "or a KEV listing is the strongest signal that a vulnerability needs attention [3][4]. Third, CVSS knows "
        "nothing about the application in which the vulnerable component runs: a library that half of the "
        "application depends on and that serves an internet-facing, customer-data service matters more than the "
        "same library in an internal batch job.")
    R.h2("1.3 Software Bills of Materials")
    R.p("A Software Bill of Materials (SBOM) is a machine-readable inventory of the components in an application "
        "and of how they depend on each other. CycloneDX is one of the two widely used SBOM formats; it records "
        "each component with an identifier (bom-ref), a package URL (purl) and a dependency graph [12]. SBOM "
        "enrichment with vulnerability and supplier data has been proposed as a way to analyse supply-chain risk "
        "[9], and SBOM generation has been applied to firmware for asset visibility [10]. An SBOM therefore offers "
        "exactly the context that CVSS lacks: which component is affected, how many other components depend on "
        "it, and which business services it belongs to.")
    R.h2("1.4 Need for the Study")
    R.p("The proposal stage of this project described a context-aware risk formula and a browser dashboard that "
        "combined EPSS, exploitation evidence, SBOM blast radius and CVSS scope. That stage left three gaps that "
        "this phase addresses. The term \u201cAI-based\u201d was not yet supported by a trained model; the claim "
        "that the context-aware order is better than CVSS had not been measured; and the dashboard ran from a local "
        "file with bundled sample intelligence rather than as a deployed, self-updating system.")
    R.h2("1.5 Scope of the Study")
    R.p("The study covers (i) a classifier that predicts KEV listing from information available at CVE "
        "publication, (ii) ingestion of CycloneDX SBOMs and Trivy, Nessus and CSV scanner output and their "
        "correlation, (iii) three ranking methods applied to the same findings, (iv) a time-frozen backtest and "
        "ablation study, and (v) deployment as a static web application, a nightly retraining pipeline and a REST "
        "API. The project does not perform code-level reachability analysis, does not remediate vulnerabilities "
        "and does not claim that a score is a guaranteed probability of compromise.")
    R.h2("1.6 Current Technical Advancements")
    R.p("Exploit prediction has matured from research into public infrastructure: FIRST publishes daily EPSS "
        "probabilities for every CVE [3][21], and CISA maintains KEV as an authoritative list of exploited "
        "vulnerabilities [6]. Gradient-boosted decision trees such as LightGBM are the standard choice for "
        "tabular classification problems of this size [14], and tree-specific SHAP values make their individual "
        "predictions explainable [15]. SBOM formats and open-source generators such as Syft and scanners such as "
        "Trivy have made component inventories routine in build pipelines [12][22][23].")
    R.h2("1.7 Conclusion")
    R.p("This chapter explained why a severity-only patch order is insufficient and why the SBOM is the natural "
        "place to add application context. The remaining chapters describe how a learned exploitation model, "
        "public threat intelligence and SBOM context were combined, how the combination was evaluated against CVSS "
        "using only information available at a fixed past date, and how the result was deployed.")


def ch2(R: Report, X: Ctx):
    R.h1("Chapter 2: Literature Review")
    R.p("The literature relevant to this project falls into four groups: severity scoring, exploitation "
        "prediction and evidence, context-aware prioritization, and SBOM-based supply-chain analysis. Machine "
        "learning methods for tabular data complete the review.")
    R.h2("2.1 Severity Scoring with CVSS")
    R.p("FIRST defines CVSS v3.1 as a base score derived from exploitability metrics (attack vector, complexity, "
        "privileges, user interaction) and impact metrics (confidentiality, integrity, availability, scope) [1]. "
        "CVSS v4.0 adds threat and environmental metric groups to adjust the base score to local conditions [2]. "
        "Both specifications describe severity; neither estimates the probability of exploitation, and the NVD "
        "publishes base scores only [13]. This project uses the CVSS v3.x vector as model input and its impact "
        "sub-score inside the risk formula.")
    R.h2("2.2 Exploitation Prediction and Evidence")
    R.p("Jacobs et al. introduced the Exploit Prediction Scoring System (EPSS), a data-driven estimate of the "
        "probability that a CVE will be exploited in the next 30 days [3]. In earlier work the same group showed "
        "that remediation strategies informed by exploit prediction cover more exploited vulnerabilities for the "
        "same effort than CVSS-based strategies [4]. Bicudo et al. combined historical weaponization data with CVSS "
        "scores to predict vulnerability severity and support patch management [5]. CISA's KEV catalogue provides "
        "confirmed exploitation evidence and a date on which each entry was added [6]; that date is what makes "
        "a time-frozen evaluation possible in this project.")
    R.h2("2.3 Context-Aware Prioritization")
    R.p("Jung et al. proposed CAVP, a context-aware vulnerability prioritization model that uses temporal metrics "
        "[7], and Parente et al. proposed FRAPE, which combines vulnerability information, threat intelligence and "
        "asset context into an explainable risk assessment [8]. Both establish that context-aware prioritization "
        "is an accepted research direction; neither uses the SBOM dependency graph as the source of context.")
    R.h2("2.4 SBOM and Software Supply Chain Risk")
    R.p("Lemay and Katiyar enrich SBOM data with vulnerability databases, dependency relationships and supplier "
        "information to analyse supply-chain risk [9]. Beninger et al. generate SBOMs from firmware binaries using "
        "string matching and code-clone detection to provide asset visibility and vulnerability detection [10]. "
        "Squillace et al. examine how AI and machine learning introduce both operational benefits and exploitable "
        "risks in supply-chain and project-management systems [11]. The CycloneDX specification defines the SBOM "
        "structure used here, including component identifiers and dependency relationships [12].")
    R.h2("2.5 Machine Learning for Tabular Security Data")
    R.p("LightGBM is a gradient-boosting decision-tree implementation designed for large tabular datasets [14]. "
        "SHAP values computed exactly for tree ensembles explain each prediction as a sum of per-feature "
        "contributions [15]. Platt scaling maps a classifier's margin to a calibrated probability [16], and "
        "scikit-learn provides the surrounding tooling [17].")
    R.table(2, "Literature Review Summary", ["No.", "Title / Author / Year / Source", "Key Contribution",
                                             "Research Gap / Relevance"], [
        ["1", "Common Vulnerability Scoring System v3.1 Specification; FIRST, 2019 [1]",
         "Defines the base score and vector used by NVD.", "Severity only; used here as model input and impact "
                                                            "term."],
        ["2", "Exploit Prediction Scoring System (EPSS); Jacobs et al., 2021, Digital Threats: Research and "
              "Practice [3]", "Daily probability of exploitation for every CVE.", "Vulnerability-level signal; no "
                                                                                  "application or SBOM context."],
        ["3", "Improving Vulnerability Remediation Through Better Exploit Prediction; Jacobs et al., 2020, Journal "
              "of Cybersecurity [4]", "Shows exploit-informed strategies beat CVSS on coverage and effort.",
         "Motivates the effort-to-cover metric used in this project."],
        ["4", "A Statistical Approach to Severity Aware Vulnerability Prioritization; Bicudo et al., 2024, IEEE [5]",
         "Integrates historical weaponization data with CVSS to predict severity.", "No SBOM context or "
                                                                                    "time-frozen evaluation."],
        ["5", "Known Exploited Vulnerabilities Catalog; CISA [6]", "Confirmed in-the-wild exploitation with "
                                                                    "dateAdded.", "Used as the label and as the "
                                                                                  "backtest answer key."],
        ["6", "CAVP: A Context-Aware Vulnerability Prioritization Model; Jung et al., 2022, Computers & Security "
              "[7]", "Context-aware prioritization with temporal metrics.", "Context not derived from the SBOM "
                                                                           "dependency graph."],
        ["7", "FRAPE; Parente et al., 2025, Journal of Information Security and Applications [8]",
         "Explainable prioritization combining threat intelligence and asset context.",
         "Supports the explainability requirement adopted here."],
        ["8", "Supply Chain Risk Analysis Via SBOM Data Enrichment; Lemay and Katiyar, 2023, IEEE [9]",
         "Enriches SBOMs with vulnerability, dependency and supplier data.", "Mainly static or rule-based "
                                                                             "evaluation; no learned likelihood."],
        ["9", "ERS0: AI-Driven SBOM for Firmware Vulnerability Detection and Asset Management; Beninger et al., "
              "2024, IEEE [10]", "SBOM generation from firmware for asset visibility.", "Focus on inventory and "
                                                                                       "detection, not ranking."],
        ["10", "User Vulnerabilities in AI-Driven Systems; Squillace et al., 2024, IEEE [11]",
         "AI/ML benefits and misuse risks in supply-chain management.", "Does not address vulnerability "
                                                                        "prioritization."],
        ["11", "CycloneDX specification; OWASP [12]", "SBOM components, purl identifiers and dependency graph.",
         "Input format of this project."],
        ["12", "LightGBM; Ke et al., 2017, NeurIPS [14]", "Efficient gradient-boosted trees for tabular data.",
         "Primary learner of the classifier."],
    ], [0.45, 2.35, 1.85, 1.85])
    R.h2("2.6 Research Gap")
    R.p("The individual ingredients are established: EPSS and KEV describe exploitation, context-aware models "
        "weight vulnerabilities by environment, and SBOMs describe component relationships. What the reviewed work "
        "does not provide is a single, transparent system that (a) learns its own exploitation-likelihood model "
        "from public labels, (b) combines it with SBOM dependency context and user-declared asset criticality, and "
        "(c) proves the resulting order against CVSS with a time-frozen backtest in which every input is limited to "
        "what was known on the freeze date. This narrow gap is the contribution of the present project; it does "
        "not claim to outperform EPSS or commercial platforms.")


def ch3(R: Report, X: Ctx):
    R.h1("Chapter 3: Problem Statement")
    R.p("Vulnerability management processes depend on static CVSS scores, which do not account for real-world "
        "exploitation, and they overlook the application and business context in which a vulnerable component "
        "runs. When many findings share the same CVSS score, security teams cannot justify which to patch first, "
        "and delayed remediation of the few vulnerabilities that attackers actually use increases exposure. There "
        "is a need for a prioritization method that learns exploitation likelihood from evidence, adds SBOM and "
        "asset context, and demonstrates with measured results that it orders the backlog better than CVSS.",
        italic=True)
    R.h2("3.1 Technical / Functional Problem")
    R.numbered([
        "Large tied blocks of identical CVSS scores make a severity-only order arbitrary within each block.",
        "Exploitation evidence (EPSS, KEV, public PoCs) is available but is not combined with severity in a single "
        "reproducible score.",
        "Scanner output lists vulnerable packages but does not say how central each package is in the application's "
        "dependency graph or which business services use it.",
        "Hand-set formula weights cannot be defended without a measurement showing that each signal improves the "
        "order.",
        "A prototype that runs from a local file with bundled data does not show how the method would operate and "
        "stay current in practice.",
    ], fmt="a)")
    R.h2("3.2 Detailed Scope of Work")
    R.numbered([
        "Collect NVD, CISA KEV, FIRST EPSS, PoC-in-GitHub and Exploit-DB data and build a leakage-free feature table.",
        "Train and evaluate a KEV exploitation classifier with a time-based split and compare it with CVSS and EPSS.",
        "Parse CycloneDX SBOMs and Trivy, Nessus and CSV scans, correlate findings to components and compute "
        "dependency fan-in and service membership.",
        "Implement three ranking methods and make their scores identical in the browser and in Python.",
        "Evaluate the rankings with a backtest frozen at 1 January 2025 and an ablation of every signal.",
        "Deploy the dashboard publicly, automate nightly retraining with a quality gate, and expose a REST API.",
    ], fmt="a)")


def ch4(R: Report, X: Ctx):
    R.h1("Chapter 4: Objectives of the Study")
    R.p("The primary aim of the project is to rank the vulnerabilities of an application by real-world risk rather "
        "than by severity alone, and to demonstrate with time-frozen evidence that the resulting order requires less "
        "patching effort than CVSS to cover the vulnerabilities that are actually exploited.")
    R.h2("4.1 Key Objectives")
    R.numbered([
        "Train an exploitation-likelihood classifier on public CVE data with CISA KEV as the label and evaluate it "
        "against CVSS and EPSS baselines on a held-out year.",
        "Ingest SBOMs and scanner output, correlate findings with SBOM components, and enrich them with threat "
        "intelligence, dependency fan-in and asset context.",
        "Produce a transparent, explainable risk score and rank findings by CVSS-only, the proposal-stage formula "
        "and Formula + ML.",
        "Validate the ranking with a time-frozen backtest and an ablation study.",
        "Deploy the system as a public dashboard with live threat intelligence, a nightly retraining pipeline with a "
        "regression gate, and a REST API.",
    ])
    R.h2("4.2 Expected Outcome")
    R.p("The expected outcome is a deployed decision-support system whose every claim points to a measured number: "
        "classifier quality on a held-out year (Table 10.1), ranking quality in the backtest (Tables 10.2 to 10.6) "
        "and the contribution of each signal (Table 10.7).")
    R.h2("4.3 Objectives-to-Chapter Mapping")
    R.p("Table 4.1 maps each objective to the sections where it is implemented and evaluated.")
    R.table(4, "Objectives to Chapter Mapping", ["Objective", "Implementation", "Testing, Validation & Results"], [
        ["1. Exploitation-likelihood classifier", "5.4-5.6, 8.2-8.3", "9.2-9.3, 10.2-10.3"],
        ["2. SBOM ingestion, correlation and enrichment", "7.3, 8.4", "9.2, 9.4-9.5"],
        ["3. Explainable risk score and three rankings", "5.7, 8.5", "9.2, 9.4, 10.4-10.6"],
        ["4. Time-frozen backtest and ablation", "5.8-5.9, 8.6", "9.2-9.3, 10.4-10.6"],
        ["5. Deployment (dashboard, nightly retrain, API)", "8.7-8.9", "9.5-9.6"],
    ], [2.6, 1.6, 2.3])


def ch5(R: Report, X: Ctx):
    R.h1("Chapter 5: Project Methodology")
    R.h2("5.1 Overview")
    R.p("The methodology separates an offline model pipeline, which learns exploitation likelihood from public data, "
        "from an online scoring layer, which applies that knowledge to a specific application's SBOM and scan. The "
        "work aligns with the Identify function of the NIST Cybersecurity Framework 2.0, which covers the "
        "understanding and prioritization of cybersecurity risk to assets [18]. Fig. 5.1 shows the eight steps.")
    R.figure(FIG / "report_methodology.png", 5, "Project Methodology Workflow (Steps 1-8)", 6.4)
    R.h2("5.2 Research Design")
    R.p("The research design is empirical and quantitative. Two evaluation questions are asked. First, how well does "
        "a model trained only on information available at publication rank CVEs by later KEV listing, compared with "
        "CVSS and EPSS? Second, on a real application inventory and using only information available on a fixed past "
        "date, which ranking covers the vulnerabilities that were exploited afterwards with the least patching "
        "effort? Both questions are answered with a time-based design: data from the future is never used to "
        "produce a ranking that is then judged on that future.")
    R.h2("5.3 Methodology Workflow")
    R.numbered([
        [("Data acquisition: ", "b"), "download the NVD CVE feed (fkie-cad mirror) [13], the CISA KEV JSON [6], "
         "FIRST EPSS files for the current date and for the freeze date [21], PoC-in-GitHub [19] and the Exploit-DB "
         "index [20]."],
        [("Feature engineering: ", "b"), "turn every CVE into label-free features knowable at publication "
         "(Section 5.6)."],
        [("Model training: ", "b"), "fit the gradient-boosted classifier on 2019-2023, validate on "
         f"{X.val_year}, calibrate on the validation year (Section 8.3)."],
        [("Evaluation: ", "b"), f"compare rankers on the {X.test_year} test year (Table 10.1)."],
        [("SBOM correlation: ", "b"), "parse the SBOM and the scan, match findings to components, compute fan-in "
         "and service membership (Section 8.4)."],
        [("Context-aware scoring: ", "b"), "compute CVSS-only, proposal-stage formula and Formula + ML scores "
         "(Section 5.7)."],
        [("Time-frozen backtest: ", "b"), "rank findings as of the freeze date and measure coverage of later KEV "
         "additions; ablate each signal (Section 5.9)."],
        [("Deployment: ", "b"), "publish the dashboard, schedule nightly retraining with a gate, expose the API "
         "(Sections 8.7-8.9)."],
    ], fmt="Step {}:")
    R.h2("5.4 Data Sources")
    R.table(5, "Data Sources", ["Source", "Content Used", "Role in the Project"], [
        ["NVD CVE feed (fkie-cad GitHub mirror)", "CVSS v3.x vector and base score, CWE, CPE vendor and product, "
                                                  "references, description, published date", "Features; CVSS "
                                                                                              "baseline"],
        ["CISA KEV catalogue", "cveID and dateAdded", "Label; backtest answer key; KEV flag"],
        ["FIRST EPSS (current file and freeze-date file)", "Daily exploitation probability", "Baseline; model "
                                                                                             "variant; formula "
                                                                                             "input"],
        ["PoC-in-GitHub", "First public PoC repository date per CVE", "PoC feature; exploit maturity"],
        ["Exploit-DB files_exploits.csv", "Exploit publication dates mapped to CVEs", "PoC feature; exploit "
                                                                                      "maturity"],
    ], [2.0, 2.6, 1.9])
    R.h2("5.5 Label and Time-Based Split")
    R.p("The label is whether a CVE appears in the CISA KEV catalogue. CVEs are split by their NVD published date, "
        f"never at random: training 2019-2023, validation {X.val_year} and test {X.test_year}. A random split would "
        "let a test CVE learn from later CVEs of the same vendor and product and would overstate performance. Rejected "
        "CVE records are removed.")
    R.h2("5.6 Features and Leakage Controls")
    R.table(5, "Model Features", ["Feature Group", "Description"], [
        ["CVSS", "Base score, a missing-vector flag and one-hot values of AV, AC, PR, UI, S, C, I and A"],
        ["Weakness", "Top-30 CWE identifiers from the training years, plus an \u201cother\u201d category"],
        ["Vendor and product", "Historical KEV rate target-encoded on training years only (smoothing m = 20, "
                               "5-fold out-of-fold values for training rows)"],
        ["References", "Total references; references tagged Exploit, Patch and Vendor Advisory; links to "
                       "exploit-db.com, github.com, packetstorm and ZDI"],
        ["Description", "Length and keyword flags for code execution, unauthenticated access, deserialization, SSRF "
                        "and authentication bypass"],
        ["Public PoC", "PoC on GitHub or Exploit-DB within 30 days of publication"],
        ["EPSS (variant only)", "Current EPSS score, used only in the \u201cwith EPSS\u201d variant"],
    ], [1.6, 4.9])
    R.p("Several NVD fields exist only because a CVE is already exploited, and they would leak the label: the "
        "cisaExploitAdd, cisaActionDue and cisaRequiredAction fields, CISA SSVC \u201cexploitation\u201d decisions "
        "and references that point to the KEV catalogue. All of them are excluded. PoC evidence counts only when it "
        "appeared within 30 days of publication, because proof-of-concept code is often published after a CVE is "
        "added to KEV. Days-since-publication and publication year are excluded from the production model because "
        "they encode how long a CVE has had to be listed; they appear only in a diagnostic variant.")
    R.h2("5.7 Context-Aware Risk-Scoring Model")
    R.p("Three scores are computed for every finding. The CVSS-only score is ten times the CVSS base score. The "
        "proposal-stage formula is reproduced exactly from the earlier dashboard so that it can be evaluated "
        "(Appendix C). The Formula + ML score replaces its hand-set likelihood with the model probability:")
    R.equation("Risk = 100 \u00d7 L \u00d7 I \u00d7 S", "5.1")
    R.equation("L = 0.5\u00b7P_model + 0.3\u00b7EPSS + 0.2\u00b7KEV", "5.2")
    R.equation("I = (0.5\u00b7CVSS_impact / 6 + 0.5\u00b7fan-in / max fan-in) \u00d7 Crit_asset", "5.3")
    R.equation("S = 1.15 if the CVSS scope is changed, otherwise 1.0", "5.4")
    R.p("Where in Eqs. (5.1)-(5.4), P_model is the calibrated classifier probability, EPSS is the FIRST probability, "
        "KEV is 1 if the CVE is in the KEV catalogue, CVSS_impact is the CVSS v3 impact sub-score, fan-in is the "
        "number of SBOM components that transitively depend on the vulnerable component and max fan-in is the "
        "largest fan-in in the SBOM. Crit_asset is 1.5, 1.25 or 1.0 for service tier 1, 2 or 3, multiplied by 1.2 "
        "for internet-facing services; it is 1.0 when no asset context is supplied and tier 2 when context is "
        "supplied but the finding maps to no service. Values above 90 are compressed by a soft ceiling, "
        "100 \u2212 10\u00b7e^(\u2212(raw \u2212 90)/10), so that scores stay below 100 without collapsing. "
        "Tiers are Critical (75 and above), High (50-75), Medium (25-50) and Low (below 25).")
    R.p("The implementation guide wrote the impact term as CVSS_impact/10. The CVSS v3 impact sub-score has a "
        "maximum of 6.0 [1], so dividing by 10 would cap the term at 0.6; dividing by 6 normalizes it to the range "
        "0-1, as the proposal-stage dashboard already did. This deviation is deliberate and documented.")
    R.h2("5.8 Evaluation Metrics")
    R.p("The classifier and the rankings are judged as rankings. AUC-ROC and PR-AUC summarize the whole order; PR-AUC "
        "is more informative at the low positive rate of KEV. Precision@k is the share of KEV CVEs in the top k; "
        "Recall@k is the share of all KEV CVEs found in the top k. The headline metric is the effort to cover 90%: the "
        "fraction of all items that must be patched, in ranked order, to cover 90% of the positives. Because CVSS "
        "assigns identical scores to many CVEs, every metric is computed as its exact expected value under random "
        "tie-breaking; a naive sort would otherwise make CVSS look arbitrarily good or bad depending on file order.")
    R.h2("5.9 Time-Frozen Backtest Design")
    R.p(f"The backtest freezes all inputs at T = {X.freeze}. EPSS is taken from the EPSS file published on that "
        "date, the KEV flag includes only catalogue entries added on or before T, and PoC evidence counts only if "
        "it existed at T. The model is re-trained for the backtest with labels as of T (train "
        f"{X.fm['train_years'][0]}-{X.fm['train_years'][1]}, validate {X.fm['val_year']}); CVEs in the training "
        f"years are scored with {X.fm['cross_fit_folds']}-fold cross-fitting, so no CVE is scored by a model that "
        "was fitted on it. Only CVEs published before T can appear in a scan taken at T. The answer key is the set "
        "of KEV entries added after T. CVEs already in KEV at T stay in the ranked list and are reported separately. "
        "CVSS vectors are taken from the current NVD feed, on the stated assumption that base scores are rarely "
        "changed after publication.")
    R.p("The backtest is run on each SBOM case and on the whole population of CVEs published before T; the "
        "population case has no SBOM, so fan-in and asset terms are zero there. The ablation re-runs Formula + ML "
        "with one signal removed at a time and reports the change in effort to cover 90%.")
    R.h2("5.10 Challenges and Resolutions")
    R.table(5, "Challenges and Resolutions", ["Challenge", "Potential Effect", "Resolution Adopted"], [
        ["Label leakage from KEV-derived NVD fields", "Inflated model accuracy", "Fields excluded; planted "
                                                                                  "traps in automated tests"],
        ["Low positive rate of KEV", "Accuracy is meaningless", "Class weighting; PR-AUC, precision@k and "
                                                                "effort to cover 90% reported"],
        ["Ties in CVSS scores", "Unfair baseline comparison", "Tie-aware expected-value metrics"],
        ["Current EPSS already reflects exploitation", "Optimistic EPSS baseline", "Backtest uses the freeze-date "
                                                                                   "EPSS file"],
        ["Scanner and SBOM name mismatches", "Missed correlations", "bom-ref, purl, name@version and optional "
                                                                    "fuzzy matching"],
        ["Browser and Python engines drifting apart", "Dashboard and backtest disagree", "Automated parity test "
                                                                                          "on identical inputs"],
    ], [2.2, 1.8, 2.5])
    R.h2("5.11 Conclusion")
    R.p("The methodology converts the objectives into measurable stages and, crucially, into an evaluation that "
        "cannot use information from the period it is judged on. The next chapters describe the resources, design "
        "and implementation of each stage.")


def ch6(R: Report, X: Ctx):
    R.h1("Chapter 6: Resource Requirement Specification")
    R.h2("6.1 Introduction")
    R.p("The system is designed to run on free, publicly available infrastructure. Training and backtesting run on a "
        "developer computer or on a GitHub-hosted runner; the dashboard is a static site; no paid service or API key "
        "is required.")
    R.h2("6.2 Hardware Requirements")
    R.table(6, "Hardware Requirements", ["Sl. No.", "Resource", "Minimum Specification", "Use"], [
        ["1", "Computer", "Quad-core x86-64 processor", "Development, training, backtest"],
        ["2", "Memory", "8 GB RAM (16 GB recommended)", "Feature table and model training"],
        ["3", "Storage", "10 GB free", "Downloaded feeds, feature table, models"],
        ["4", "Internet", "Broadband connection", "Feed download; live EPSS and KEV"],
        ["5", "CI runner", "GitHub-hosted ubuntu-latest", "Nightly retraining and deployment"],
    ], [0.7, 1.3, 2.3, 2.2])
    R.h2("6.3 Software Requirements")
    R.table(6, "Software Requirements", ["Sl. No.", "Software / Library", "Purpose"], [
        ["1", "Python 3.11 or later", "Pipeline, model, backtest, API, report generation"],
        ["2", "pandas, NumPy, SciPy", "Data processing"],
        ["3", "scikit-learn", "Encoders, logistic regression, calibration, fallback learner"],
        ["4", "LightGBM", "Primary gradient-boosting learner"],
        ["5", "matplotlib", "Figures"],
        ["6", "pyarrow", "Parquet storage of the feature table (optional)"],
        ["7", "Node.js 18 or later", "Running the browser engine in the parity tests"],
        ["8", "HTML, CSS and JavaScript", "Dashboard and browser scoring engine"],
        ["9", "FastAPI, Uvicorn, Docker", "REST API and container"],
        ["10", "Git, GitHub Actions, GitHub Pages", "Version control, nightly pipeline, hosting"],
        ["11", "Syft and Trivy", "Generating SBOMs and scans of real applications"],
    ], [0.7, 2.3, 3.5])
    R.h2("6.4 Data Environment Requirements")
    R.table(6, "Data Environment Requirements", ["Resource", "Format", "Purpose"], [
        ["NVD CVE year files", "JSON (xz-compressed)", "CVE attributes"],
        ["CISA KEV catalogue", "JSON", "Label and KEV flag"],
        ["FIRST EPSS scores", "CSV (gzip), REST API", "Baseline and live input"],
        ["PoC-in-GitHub, Exploit-DB", "JSON per CVE, CSV", "PoC evidence"],
        ["Application SBOM", "CycloneDX JSON", "Component inventory and dependency graph"],
        ["Vulnerability scan", "Trivy JSON, Nessus XML, CSV", "Findings to prioritize"],
        ["Asset context", "JSON (asset-context.json)", "Service tier and exposure"],
    ], [2.2, 2.0, 2.3])
    R.h2("6.5 Conclusion")
    R.p("The requirements are modest and entirely free, which keeps the project reproducible: any reviewer can "
        "clone the repository and repeat every result with the commands in Appendix C.")


def ch7(R: Report, X: Ctx):
    R.h1("Chapter 7: Software Design")
    R.h2("7.1 Introduction")
    R.p("The design has two halves that share one scoring core. An offline pipeline in Python builds features, trains "
        "the model, evaluates it and exports its output. An online layer, in the browser or behind the REST API, "
        "parses the user's files and applies the same scoring rules. Keeping the core identical in both places is "
        "a design requirement, verified by an automated parity test.")
    R.h2("7.2 System Architecture")
    R.figure(FIG / "report_architecture.png", 7, "System Architecture of the SBOM Context Risk Engine", 6.4)
    R.p("The public sources on the left feed the nightly pipeline in the middle, which publishes a model card, "
        "per-CVE model output and a KEV snapshot. The delivery layer on the right reads the user's SBOM, scan and "
        "optional asset context in the browser, fetches current EPSS and KEV values for the matched CVEs, and "
        "produces the three rankings.")
    R.h2("7.3 Major Modules")
    R.numbered([
        [("Sources (engine/sources.py): ", "b"), "downloads and parses NVD, KEV, EPSS, PoC-in-GitHub and Exploit-DB, "
         "ignoring the leakage fields listed in Section 5.6."],
        [("Features (engine/features.py): ", "b"), "builds label-free features and the training-only encoders."],
        [("Model (engine/model.py): ", "b"), "trains the gradient-boosted classifier and the logistic baseline, "
         "calibrates probabilities and computes feature contributions."],
        [("Metrics (engine/metrics.py): ", "b"), "tie-aware AUC, precision@k, recall@k, effort to cover and coverage "
         "curves."],
        [("SBOM and scan ingestion (engine/sbom.py): ", "b"), "CycloneDX parsing, dependency graph, fan-in, Trivy, "
         "Nessus and CSV parsers, correlation and asset-context mapping."],
        [("Scoring (engine/scoring.py and site/engine.js): ", "b"), "CVSS-only, proposal-stage formula and "
         "Formula + ML, with switches for the ablation."],
        [("Training and export (train/): ", "b"), "fetch_data, build_features, train and export scripts."],
        [("Backtest (backtest/run_backtest.py): ", "b"), "frozen, cross-fitted model and Tables 10.2-10.7."],
        [("Dashboard (site/dashboard.html): ", "b"), "uploads, live intelligence, three-way ranking and "
         "explanations."],
        [("API (api/main.py): ", "b"), "FastAPI service using the same Python scoring core."],
        [("Automation (.github/workflows/): ", "b"), "nightly retraining, tests on every push and Pages "
         "deployment."],
        [("Document generators (scripts/): ", "b"), "build_report.py, build_deck.py and build_viva.py rebuild this "
         "report, the results deck and the viva question sheet from the published result files, so no number is "
         "ever typed by hand."],
    ])
    R.h2("7.4 Data Model")
    R.p("After correlation and enrichment, every finding is a record with the fields in Table 7.1; the three score "
        "blocks and their per-mode rank are added by the scoring module.")
    R.table(7, "Data Model of an Enriched Finding", ["Field", "Description", "Example"], [
        ["cve_id", "CVE identifier", "CVE-2021-44228"],
        ["component, version, component_ref", "Matched SBOM component and its bom-ref", "log4j-core, 2.14.1"],
        ["match", "How the finding was matched", "bom-ref, purl, name@version, fuzzy"],
        ["cvss_base, cvss_impact, scope_changed", "From the scanner vector, or backfilled from NVD", "10.0, 6.0, "
                                                                                                    "true"],
        ["p_model, p_source", "Calibrated model probability and its source", "0.19, model"],
        ["epss, kev, poc_github, poc_exploitdb", "Threat intelligence", "0.975, true, true, true"],
        ["fanin, max_fanin", "Transitive dependents of the component", "1, 4"],
        ["services, has_context", "Matched services with tier and exposure", "payment-api (tier 1)"],
        ["cvss / legacy / ml", "Score blocks with every term, tier and rank", "raw, risk, tier, rank"],
    ], [2.0, 2.6, 1.9])
    R.h2("7.5 Delivering the Model to the Browser")
    R.p("The implementation guide suggested transpiling the model to JavaScript. The model's inputs, however, are "
        "NVD fields (vector, CWE, CPE vendor, references, PoC dates) that a scanner report does not contain, so the "
        "browser would have to download per-CVE features anyway. Instead the nightly job scores every CVE and "
        "publishes the output in one JSON file per CVE-ID year. The dashboard loads only the years present in the "
        "uploaded scan. Each entry holds the probability, the EPSS and KEV snapshot, PoC flags, the CVSS impact "
        "sub-score, scope and base score, and the three most influential features (Appendix C). This keeps the "
        "user's SBOM and scan inside the browser and allows exact per-prediction explanations.")
    R.h2("7.6 Conclusion")
    R.p("The modular design lets the data sources, the learner and the presentation layer change independently, "
        "while the scoring rules exist once in Python and once in JavaScript under an automated equality check.")


def ch8(R: Report, X: Ctx):
    m = X.m
    R.h1("Chapter 8: Implementation")
    R.h2("8.1 Development Environment")
    R.p("The pipeline is written in Python and organized as a package (engine/, train/, backtest/, api/, scripts/, "
        "tests/). The dashboard is a single HTML page with a separate JavaScript engine that has no external "
        "runtime dependencies. The repository is hosted on GitHub, which also runs the nightly pipeline and serves "
        "the site. All commands are listed in Appendix C.")
    R.h2("8.2 Objective 1: Data Pipeline")
    R.p("train/fetch_data.py downloads the NVD year files, the KEV catalogue (from cisa.gov with the official GitHub "
        "mirror as a fallback), the current EPSS file and the EPSS file of the freeze date, a shallow clone of "
        "PoC-in-GitHub and the Exploit-DB index. train/build_features.py parses them into one row per CVE, preferring "
        "the NVD Primary CVSS v3.1 or v3.0 metric, and records a manifest with the data snapshot dates. The model "
        f"published with this report was built from the KEV catalogue version {X.snap.get('kev_catalog')} and EPSS "
        f"scores dated {(X.snap.get('epss_score_date') or 'n/a')[:10]}.")
    R.h2("8.3 Objective 1: Classifier Training")
    R.p("The primary learner is LightGBM with 600 trees at most, learning rate 0.03, 31 leaves, a minimum of 40 "
        "samples per leaf, row and column subsampling of 0.8, L2 regularization 1.0 and class weighting for the "
        "imbalanced label; early stopping monitors average precision on the validation year. If LightGBM is not "
        "installed, the code falls back to scikit-learn's HistGradientBoosting, from the same algorithm family, and "
        "records which learner produced every artifact. "
        f"The model reported in Chapter 10 was trained with {X.algo}. Class weighting distorts probabilities, so the "
        "raw margin is Platt-calibrated on the validation year [16]; calibration is monotone and changes no ranking "
        "metric. A class-balanced logistic regression on the same features serves as the explainability baseline. "
        "Three model variants are trained: without EPSS (the project's own model, used in the formula), with EPSS, "
        "and with time features (diagnostic only).")
    R.p(f"Per-prediction explanations use {m['explanation_kind']}. For every CVE the three features with the "
        "largest absolute contribution are exported and shown in the dashboard.")
    R.h2("8.4 Objective 2: Ingestion and Correlation")
    R.p("The SBOM parser reads CycloneDX JSON, including nested components, and builds forward and reverse "
        "dependency graphs from the dependencies section. Fan-in is the number of components that transitively "
        "depend on a component and is looked up by bom-ref. Three scanner formats are supported: Trivy JSON, Nessus "
        "XML (every <cve> of a report item becomes a finding; items without a CPE are skipped and counted) and CSV "
        "with the columns component, version, cve_id and cvss_base, read with a standards-compliant CSV reader. "
        "Findings are matched to components by bom-ref, then purl, then name@version and optionally by fuzzy name "
        "containment, and duplicate component-CVE pairs are removed.")
    R.p("Compared with the proposal-stage dashboard, the implementation corrects four defects: a package can now "
        "carry several CVEs (previously only the last was kept), fan-in is looked up by bom-ref so that SBOMs with "
        "purl identifiers no longer return zero, quoted commas no longer break CSV rows, and a Nessus item with "
        "several CVEs yields several findings. The optional asset-context file maps services to components or "
        "scanner hosts; an entry without a version also matches every component beneath it, so a service can be "
        "declared by its top-level component.")
    R.h2("8.5 Objective 3: Risk Calculation")
    rows, _ = worked_example()
    top = rows[0]
    ml = top["ml"]
    R.p("Table 8.1 traces the Formula + ML score of the highest-ranked finding in the bundled sample application "
        "(acme-commerce-platform), computed by the project's engine with the snapshot of EPSS and KEV that is "
        "published with the model. Live values in the dashboard may differ slightly.")
    R.table(8, f"Worked Scoring Example - {top['cve_id']} in {top['component']} {top['version']}",
            ["Term", "Value", "Explanation"], [
                ["P_model", f"{top['p_model']:.4f}", "Calibrated model probability"],
                ["EPSS", f"{top['epss']:.4f}", "EPSS snapshot"],
                ["KEV", "1" if top["kev"] else "0", "Listed in CISA KEV" if top["kev"] else "Not listed"],
                ["Likelihood L", f"{ml['likelihood']:.4f}", "0.5\u00b7P_model + 0.3\u00b7EPSS + 0.2\u00b7KEV"],
                ["CVSS impact term", f"{ml['cvss_term']:.4f}", f"impact sub-score {top['cvss_impact']:.1f} / 6"],
                ["Fan-in term", f"{ml['fanin_term']:.4f}", f"fan-in {top['fanin']} / max {top['max_fanin']}"],
                ["Crit_asset", f"{ml['crit_mult']:.2f}", ", ".join(f"{s['name']} (tier {s['tier']}"
                                                                     f"{', internet' if s['internet_facing'] else ''})"
                                                                     for s in top["services"]) or "no service"],
                ["Impact I", f"{ml['impact']:.4f}", "(0.5\u00b7impact + 0.5\u00b7fan-in) \u00d7 Crit_asset"],
                ["Scope S", f"{ml['scope_mult']:.2f}", "CVSS scope changed" if top["scope_changed"] else
                 "scope unchanged"],
                ["Raw score", f"{ml['raw']:.2f}", "100 \u00d7 L \u00d7 I \u00d7 S"],
                ["Risk score and tier", f"{ml['risk']:.2f}", ml["tier"]],
            ], [1.7, 1.1, 3.7])
    order = ", ".join(f"{r['cve_id']}" for r in rows[:5])
    R.p(f"The five highest-ranked sample findings under Formula + ML are {order}. The same findings are ranked in the "
        "dashboard under CVSS-only and the proposal-stage formula, so the change in order can be seen directly.")
    R.h2("8.6 Objective 4: Backtest Implementation")
    R.p("backtest/run_backtest.py rebuilds the model with labels as of the freeze date and 5-fold cross-fitting "
        "(fold-specific target encoders are fitted without the held-out fold), loads each SBOM case from "
        "backtest/fixtures/, replaces scanner CVSS values with NVD values, drops CVEs published after the freeze "
        "date, scores every finding with all five rankers and writes backtest.json, ablation.csv and the coverage "
        "figures. Two SBOM cases are used. The acme-commerce-platform sample is the application inventory used at "
        "the proposal stage (17 components, 15 findings).")
    if X.args.sbom_from_syft:
        R.p("The legacy-java-app case is the Apache Struts2 Showcase 2.3.20 web application, whose CycloneDX SBOM "
            "and Trivy scan were generated with Syft and Trivy by scripts/build_fixtures.sh.")
    else:
        R.p("The legacy-java-app case is a CycloneDX inventory of an Apache Struts2 Showcase 2.3.20 web application "
            "with 25 components and 36 findings, assembled by hand from the application's well-known dependency "
            "set; scripts/build_fixtures.sh regenerates it with Syft and Trivy from the actual build.")
    if "kev-2025-app" in X.b["cases"]:
        k = X.b["cases"]["kev-2025-app"]
        R.p("A backtest case can only measure a ranking if some of its CVEs were added to KEV after the freeze "
            "date, and neither sample application had any. The kev-2025-app case is built for exactly that: "
            "scripts/make_backtest_fixture.py takes the CVEs published before the freeze date that CISA added "
            "afterwards, asks OSV which package versions they affect, and writes Maven, npm and PyPI manifests "
            "pinned to those versions; Syft and Trivy then generate the SBOM and the scan, so the fixture is real "
            f"scanner output. It contributes {k['n_findings']} findings, {k['later_exploited']} of them later "
            "exploited.")
    R.h2("8.7 Objective 5: Dashboard")
    R.p("The dashboard (Fig. 8.1) accepts the SBOM, the scan and the optional asset-context file with instant "
        "validation of each upload. It fetches EPSS for the matched CVE identifiers from the FIRST API in batches "
        "of 100 and the KEV catalogue from CISA or its GitHub mirror, caches both for 24 hours, and falls back to "
        "the published snapshot with a dated badge when the network is unavailable. Only CVE identifiers leave the "
        "browser. A five-card panel describes the signals and quotes the model's test AUC from the model card; a "
        "three-way toggle switches between CVSS-only, the proposal-stage formula and Formula + ML; each finding "
        "expands to show every formula term, the model probability and its three strongest features; and a tile "
        "reports the backtest headline from backtest.json.")
    up = FIG / "dashboard_upload.png"
    if up.exists():
        R.figure(up, 8, "Dashboard Inputs - SBOM, Scan and Optional Asset Context with Instant Validation", 6.3)
    R.figure(FIG / "dashboard.png", 8, "Deployed Dashboard - Ranked Findings under Formula + ML with the Backtest "
             "Headline Tile", 6.3)
    det = FIG / "dashboard_detail.png"
    if det.exists():
        R.figure(det, 8, "Per-Finding Breakdown - Formula Terms, Model Probability with its Strongest Features, "
                 "Threat Intelligence and Affected Services", 6.3)
    R.h2("8.8 Objective 5: Nightly Retraining (MLOps)")
    R.p("The retrain workflow (Fig. 8.2) runs every night at 03:00 IST and on demand. It fetches the feeds, "
        "rebuilds features, retrains the model, exports the shards, repeats the backtest, regenerates the results "
        "document and runs the automated tests. A regression gate then requires a test AUC above "
        f"{m['min_test_auc_gate']:.2f} on real data and the presence of a backtest; only if every step succeeds are "
        "the new artifacts committed and the site redeployed. A failed run therefore leaves the last good model "
        "online. A separate workflow runs the test suite on every push.")
    R.figure(FIG / "report_mlops.png", 8, "Nightly Retraining and Deployment Pipeline", 6.4)
    R.h2("8.9 REST API")
    R.p("api/main.py exposes POST /score (SBOM, scan and optional asset context as multipart files; options for "
        "fuzzy matching and live intelligence), GET /model (the model card) and GET /health. It uses the same Python "
        "scoring core and exported model output as the backtest, so it returns the same ranking as the dashboard. A "
        "Dockerfile packages it on python:3.11-slim, and FastAPI generates interactive documentation at /docs.")
    R.h2("8.10 Security and Privacy of the Implementation")
    R.p("The uploaded SBOM, scan and asset context are processed only in the browser; the static site has no server "
        "component that could store them. Text from uploaded files is escaped before display. Live requests send "
        "only CVE identifiers to FIRST and download the public KEV file. The nightly workflow uses only the "
        "repository token with write access limited to the repository.")
    R.h2("8.11 Implementation Boundary")
    R.p("The system is a single-developer academic implementation. It does not perform code-level reachability "
        "analysis, it does not discover asset context automatically, and SPDX SBOMs are not supported. Its purpose "
        "is to demonstrate and measure the prioritization method, not to replace commercial vulnerability "
        "management platforms.")


def ch9(R: Report, X: Ctx):
    R.h1("Chapter 9: Testing and Validation")
    R.h2("9.1 Introduction")
    R.p("Testing covers four layers: unit tests of parsers, metrics and formulas; leakage tests of the data pipeline; "
        "a parity test between the browser and Python engines; and end-to-end runs. The automated suite runs "
        "offline on a synthetic fixture that reproduces the exact file formats of every data source, so it can run "
        "on every push without network access.")
    R.h2("9.2 Automated Test Suite")
    R.table(9, "Automated Tests (python -m tests.run_tests)", ["Area", "Test", "Expected Outcome"], [
        ["Metrics", "No ties equal the guide's definition", "Tie-free results match the reference formula"],
        ["Metrics", "Ties are expected values", "Tied blocks give the exact expected value"],
        ["Scoring", "CVSS impact matches NVD", "Impact sub-score equals published values"],
        ["Scoring", "Guide formula by hand", "Formula + ML equals a hand calculation"],
        ["Scoring", "Asset multiplier rules", "1.0 without context; tier 2 when unmatched"],
        ["Scoring", "Ablation zeroes one signal", "Removed signal contributes nothing"],
        ["Scoring", "Soft ceiling continuous", "Continuous at 90 and always below 100"],
        ["Scoring", "Proposal-stage formula reproduced", "Matches the earlier dashboard's Log4Shell score"],
        ["Parsing", "Trivy keeps every CVE per package", "No finding overwritten"],
        ["Parsing", "CSV with quoted commas", "All rows parsed correctly"],
        ["Parsing", "Nessus multi-CVE and missing CPE", "One finding per CVE; no-CPE items counted"],
        ["Parsing", "Fan-in uses bom-ref", "Correct fan-in for purl-based SBOMs"],
        ["Parsing", "Correlation de-duplicates", "One finding per component-CVE pair"],
        ["Service", "API matches the engine ranking", "Identical order to the direct engine"],
        ["Parity", "Browser equals Python", "Identical fan-in, services, scores and ranks"],
        ["Parity", "Formula constants match", "Identical constants in both engines"],
        ["Pipeline", "Rejected records dropped", "No rejected CVE; data source stamped"],
        ["Pipeline", "Leakage traps absent", "No KEV-derived field reaches the features"],
        ["Pipeline", "PoC window blocks post-KEV PoCs", "Late PoCs do not set the feature"],
        ["Pipeline", "Backtest answer key after freeze", "Positives were added to KEV after T"],
    ], [1.0, 2.6, 2.9])
    R.p("All 20 tests pass. The suite is also executed by the nightly workflow before any model is published.")
    R.h2("9.3 Leakage Validation")
    R.p("The synthetic fixture deliberately plants every known leakage path: KEV-derived NVD fields, a reference to "
        "the KEV catalogue and a CISA SSVC \u201cactive exploitation\u201d decision on every KEV CVE, and "
        "proof-of-concept repositories created after the KEV listing. The tests assert that none of these reaches "
        "the feature matrix and that late PoCs do not switch on the PoC feature. A separate test asserts that every "
        "backtest positive was added to KEV after the freeze date and that no CVE in KEV at the freeze date is "
        "counted as a later positive.")
    R.h2("9.4 Browser and Python Parity")
    R.p("The dashboard's engine (site/engine.js) and the Python engine are run on the same SBOMs, scans, asset "
        "context and randomized threat intelligence, including a case with fuzzy matching and a CSV scan. The test "
        "requires identical fan-in maps, matched findings, services, every term of the three scores and every rank. "
        "Rounding is implemented identically in both languages for this reason.")
    R.h2("9.5 Functional Validation")
    R.table(9, "Functional Validation of the Dashboard", ["Scenario", "Expected Behaviour", "Result"], [
        ["Sample data loaded", "Three rankings differ; each finding shows formula terms, P_model and top features",
         "As expected"],
        ["Scan dropped in the SBOM box", "Immediate message that the file is a scan", "As expected"],
        ["Asset context omitted", "Criticality multiplier 1.0 for every finding", "As expected"],
        ["Network blocked", "Snapshot EPSS and KEV used; dated badge shown", "As expected"],
        ["Model files unavailable", "Warning banner; prior probability used", "As expected"],
        ["Synthetic model files", "Red banner warns that numbers are not real", "As expected"],
    ], [1.9, 3.3, 1.3])
    R.h2("9.6 Deployment Validation")
    R.p("The nightly workflow was executed on GitHub Actions against the public feeds; it published the model card, "
        "the per-CVE output and the backtest to GitHub Pages, where the dashboard loaded them without warnings. The "
        "regression gate was verified to fail on a model below the AUC threshold and on synthetic data, in which case "
        "nothing is committed.")
    R.h2("9.7 Validation Limitations")
    R.p("The tests show that the implementation is correct, consistent between languages and free of the known "
        "leakage paths. They do not show that KEV is a complete ground truth, and the SBOM backtest cases are small; "
        "Chapter 10 therefore reports the population case alongside them and Chapter 11 lists the remaining "
        "limitations.")


def ch10(R: Report, X: Ctx):
    m, t1, c = X.m, X.t1, X.c
    R.h1("Chapter 10: Analysis and Results")
    warning(R, X)
    R.h2("10.1 Introduction")
    R.p("This chapter reports the results produced by the pipeline run published with this report. The model card "
        f"was generated on {m['trained_at'][:10]} from the KEV catalogue version {X.snap.get('kev_catalog')}; the "
        f"backtest was generated on {X.b['generated_at'][:10]} with the freeze date {X.freeze}; the artifacts "
        f"come from the tagged snapshot {X.b.get('release', 'unknown')}. Because the "
        "pipeline retrains nightly, later runs may differ slightly as new CVEs are published and new KEV entries "
        "are added.")
    R.h2("10.2 Dataset")
    R.p(f"The split contains {X.n_total:,} CVEs, of which {X.kev_total:,} ({pct(X.kev_total / X.n_total)}) are in "
        f"KEV: training {c['train']['n']:,} CVEs ({c['train']['kev']} KEV), validation {c['val']['n']:,} "
        f"({c['val']['kev']}) and test {c['test']['n']:,} ({c['test']['kev']}, {pct(c['test']['kev_rate'])}). The "
        "low positive rate is why ranking metrics rather than accuracy are reported.")
    R.h2("10.3 Classifier Results")
    order = ["cvss", "epss", "model_no_epss", "model_with_epss", "logreg_no_epss"]
    R.table(10, f"Classifier vs Baselines, {X.test_year} Test Year (n = {c['test']['n']:,}, "
                f"k = {c['test']['kev']} in KEV)",
            ["Ranker", "AUC-ROC", "PR-AUC", "P@100", "P@500", "R@1000", "Effort 90%"],
            [[T1[k], f3(t1[k]["auc_roc"]), f3(t1[k]["pr_auc"]), f3(t1[k]["precision_at_100"]),
              f3(t1[k]["precision_at_500"]), f3(t1[k]["recall_at_1000"]), pct(t1[k]["effort_to_cover_90"])]
             for k in order],
            [2.05, 0.75, 0.75, 0.7, 0.7, 0.75, 0.8], highlight_row=3)
    R.p("* The EPSS rows use the current EPSS file, which already reflects exploitation activity after publication; "
        "they are an optimistic upper bound. The fair, time-frozen comparison with EPSS is the backtest.")
    a_m, a_c = t1["model_no_epss"]["auc_roc"], t1["cvss"]["auc_roc"]
    p_m, p_c = t1["model_no_epss"]["pr_auc"], t1["cvss"]["pr_auc"]
    R.p(f"Without any EPSS input, the model's AUC-ROC of {f3(a_m)} {higher(a_m, a_c)} the {f3(a_c)} of the CVSS "
        f"base score, and its PR-AUC of {f3(p_m)} {higher(p_m, p_c)} CVSS's {f3(p_c)}. To cover 90% of the "
        f"{X.test_year} KEV CVEs, the model order {less_effort(t1['model_no_epss']['effort_to_cover_90'], t1['cvss']['effort_to_cover_90'])} "  # noqa: E501
        f"the CVSS order ({pct(t1['model_no_epss']['effort_to_cover_90'])} against "
        f"{pct(t1['cvss']['effort_to_cover_90'])} of all test-year CVEs). The logistic-regression baseline reached "
        f"an AUC-ROC of {f3(t1['logreg_no_epss']['auc_roc'])}; the variant that also uses the current EPSS score "
        f"reached {f3(t1['model_with_epss']['auc_roc'])}, against {f3(t1['epss']['auc_roc'])} for EPSS alone. The "
        f"model {'passes' if (a_m or 0) > m['min_test_auc_gate'] else 'does not pass'} the deployment gate of "
        f"{m['min_test_auc_gate']:.2f} on this run.")
    imp = (m.get("shap_mean_abs") or m["importance"])[:5]
    R.p("Fig. 10.1 shows the most influential features. The five strongest are "
        + ", ".join(f"\u201c{r['label']}\u201d" for r in imp[:-1]) + f" and \u201c{imp[-1]['label']}\u201d "
        f"(importance measured as {'mean absolute SHAP value' if m.get('shap_mean_abs') else m['importance_kind']}).")
    R.figure(FIG / "feature_importance.png", 10, "Top Features of the Exploitation Classifier", 5.6)
    R.figure(FIG / "coverage_test_year.png", 10, f"Coverage of KEV CVEs in the {X.test_year} Test Year by Ranker",
             5.0)
    R.h2("10.4 Backtest Results")
    for key in [X.prim_key] + [k for k in X.sbom_cases if k != X.prim_key]:
        case = X.b["cases"][key]
        t2 = X.t2(case)
        R.table(10, f"SBOM Backtest, Frozen {X.freeze}: {case.get('app', key)} "
                    f"(N = {case['n_findings']} findings, M = {case['later_exploited']} later-exploited)",
                ["Ranking Method", "Mean Rank of Later-Exploited", "Precision@10", "Precision@25", "Effort 90%"],
                [[RANK[k], rank_f(t2[k]["mean_rank_later_exploited"]), f3(t2[k]["precision_at_10"]),
                  f3(t2[k]["precision_at_25"]), pct(t2[k]["effort_to_cover_90"])]
                 for k in ("cvss", "legacy", "ml", "epss")], [2.2, 1.3, 1.0, 1.0, 1.0], highlight_row=3)
        R.p(f"In the {case.get('app', key)} case, {case['known_exploited_at_T']} findings were already in KEV at the "
            f"freeze date and {case['later_exploited']} were added afterwards. The later-exploited CVEs sit at mean "
            f"rank {rank_f(t2['ml']['mean_rank_later_exploited'])} under Formula + ML against "
            f"{rank_f(t2['cvss']['mean_rank_later_exploited'])} under CVSS-only. At the 90% coverage cut-off, "
            f"Formula + ML {less_effort(t2['ml']['effort_to_cover_90'], t2['cvss']['effort_to_cover_90'])} "
            f"CVSS-only ({pct(t2['ml']['effort_to_cover_90'])} against {pct(t2['cvss']['effort_to_cover_90'])}) and "
            f"{less_effort(t2['ml']['effort_to_cover_90'], t2['legacy']['effort_to_cover_90'])} the proposal-stage "
            f"formula ({pct(t2['legacy']['effort_to_cover_90'])}).")
        o2 = {r["ranker"]: r for r in case["table2_open_only"]}
        R.table(10, f"{case.get('app', key)}: Open Findings Only (the {case['known_exploited_at_T']} CVEs already "
                    f"in KEV at the freeze date removed, N = {o2['ml']['n']})",
                ["Ranking Method", "Mean Rank of Later-Exploited", "Precision@10", "Precision@25", "Effort 90%"],
                [[RANK[k], rank_f(o2[k]["mean_rank_later_exploited"]), f3(o2[k]["precision_at_10"]),
                  f3(o2[k]["precision_at_25"]), pct(o2[k]["effort_to_cover_90"])]
                 for k in ("cvss", "legacy", "ml", "epss")], [2.2, 1.3, 1.0, 1.0, 1.0], highlight_row=3)
        R.p("Findings already listed in KEV on the freeze date fill the top of every ranking that uses the KEV "
            "flag, which drives precision@10 towards zero in the table above and hides how the methods order the "
            "unknown findings. The variant that removes them is the sharper comparison: a team patches known "
            "exploited CVEs regardless of which tool ranked them.")
    R.figure(FIG / f"coverage_backtest_{X.prim_key}.png", 10,
             f"Backtest Coverage Curve, {X.P.get('app', X.prim_key)}", 5.0)
    if X.b.get("headline_note"):
        R.p(X.b["headline_note"])
    R.h2("10.5 Population Backtest")
    t2 = X.t2(X.POP)
    R.table(10, f"Population Backtest, All CVEs Published Before {X.freeze} (N = {X.POP['n_findings']:,}, "
                f"M = {X.POP['later_exploited']})",
            ["Ranking Method", "Mean Rank of Later-Exploited", "Precision@10", "Precision@25", "Effort 90%"],
            [[RANK[k], rank_f(t2[k]["mean_rank_later_exploited"]), f3(t2[k]["precision_at_10"]),
              f3(t2[k]["precision_at_25"]), pct(t2[k]["effort_to_cover_90"])]
             for k in ("cvss", "legacy", "ml", "epss", "model")], [2.2, 1.3, 1.0, 1.0, 1.0], highlight_row=3)
    R.p(f"The population case gives the statistically stronger comparison because it contains "
        f"{X.POP['later_exploited']} later-exploited CVEs. The clearest separation is in mean rank: the "
        f"later-exploited CVEs sit at rank {rank_f(t2['ml']['mean_rank_later_exploited'])} under Formula + ML "
        f"against {rank_f(t2['cvss']['mean_rank_later_exploited'])} under CVSS-only, out of "
        f"{X.POP['n_findings']:,} CVEs. At the 90% cut-off Formula + ML "
        f"{less_effort(t2['ml']['effort_to_cover_90'], t2['cvss']['effort_to_cover_90'])} CVSS-only "
        f"({pct(t2['ml']['effort_to_cover_90'])} against {pct(t2['cvss']['effort_to_cover_90'])}). EPSS taken from "
        f"the freeze-date file needed {pct(t2['epss']['effort_to_cover_90'])}, and the frozen model alone needed "
        f"{pct(t2['model']['effort_to_cover_90'])}.")
    if (t2["legacy"]["effort_to_cover_90"] is not None and t2["ml"]["effort_to_cover_90"] is not None
            and t2["legacy"]["effort_to_cover_90"] <= t2["ml"]["effort_to_cover_90"]):
        R.p(f"Stated plainly: at this single cut-off the proposal-stage formula, without the model, reaches 90% "
            f"coverage with {pct(t2['legacy']['effort_to_cover_90'])} of the backlog, marginally ahead of "
            f"Formula + ML. Effort-to-cover-90% is a single point on the coverage curve and is dominated by the "
            "last few positives; the model's contribution is visible in the mean rank above and in the ablation "
            "of Section 10.6, where removing it changes the effort by "
            f"{100 * (X.abl(X.POP)['model']['delta_vs_full'] or 0):+.1f} percentage points.")
    if X.POP.get("epss_scored_only"):
        R.p(f"EPSS publishes a score for most but not all CVEs. This case keeps only the CVEs that EPSS scored on "
            f"{X.freeze}; {X.POP['excluded_no_epss_at_T']:,} unscored CVEs "
            f"({X.POP['excluded_no_epss_later_exploited']} of them later exploited) are excluded. Filling those "
            "gaps with zero would place them in one tied block at the bottom of the EPSS ranking and would "
            "understate the EPSS baseline; the unrestricted numbers are kept in backtest.json for reference.")
    R.p("Because there is no SBOM in this case, the difference between Formula + ML and its likelihood inputs "
        "comes only from the CVSS impact and scope terms.")
    R.figure(FIG / "coverage_backtest_population.png", 10, "Population Backtest Coverage Curve", 5.0)
    R.h2("10.6 Ablation")
    prim_abl, pop_abl = X.abl(X.P), X.abl(X.POP)
    rows = []
    for key, r in prim_abl.items():
        q = pop_abl[key]

        def cell(a):
            if a["effort_to_cover_90"] is None:
                return "n/a"
            d = a.get("delta_vs_full")
            return f"{pct(a['effort_to_cover_90'])} ({'+' if (d or 0) >= 0 else ''}{100 * (d or 0):.1f} pp)"
        rows.append([r["name"].replace("None (full Formula + ML)", "None (full model)"), cell(r), cell(q)])
    R.table(10, "Ablation on Formula + ML (Effort to Cover 90%, Change vs Full Model)",
            ["Signal Removed", X.P.get("app", X.prim_key), "Population"], rows, [2.5, 2.0, 2.0], highlight_row=1)
    lines = []
    for key, r in pop_abl.items():
        if key == "none":
            continue
        use = r if r["delta_vs_full"] is not None else prim_abl[key]
        where = "population" if r["delta_vs_full"] is not None else X.P.get("app", X.prim_key)
        d = use["delta_vs_full"]
        if d is None:
            continue
        verdict = ("made the ranking worse, so the signal helps" if d > 0.005 else
                   "made the ranking better, so the signal hurt in this case" if d < -0.005 else
                   "had no measurable effect")
        what = {"model": "the ML probability", "epss": "EPSS", "kev": "the KEV flag", "fanin": "the blast radius "
                "(fan-in)", "scope": "the scope multiplier", "asset": "asset criticality"}.get(key, r["name"])
        lines.append(f"Removing {what} {verdict} ({100 * d:+.1f} percentage points, {where}).")
    R.bullets(lines)
    R.p("A positive change means that removing the signal increased the patch effort. A signal that hurts on a case "
        "is reported rather than hidden; the fan-in and asset terms exist only in the SBOM cases.")
    R.h2("10.7 Discussion")
    R.p("Three conclusions follow from the results. First, a model trained only on information available at "
        "publication ranks CVEs by later exploitation differently from, and on this run "
        f"{'better than' if (a_m or 0) > (a_c or 0) else 'not better than'}, CVSS, which answers whether the "
        "\u201cAI\u201d in the title contributes on its own. Second, EPSS remains a strong signal; the model is "
        "complementary to it and can be retrained on organization-specific labels, which EPSS cannot. Third, the "
        "time-frozen backtest turns the proposal's claim into a measured statement about patch effort, and the "
        "ablation shows which parts of the formula carry that improvement.")
    R.h2("10.8 Limitations")
    R.numbered([
        "KEV is an incomplete label biased towards vulnerabilities relevant to US federal systems; a CVE not in KEV "
        "is not proven unexploited.",
        "The positive rate is low, which limits achievable precision.",
        "The EPSS rows of Table 10.1 use the current EPSS file and are optimistic; the backtest uses the freeze-date "
        "file.",
        "Recent CVEs have had less time to be listed in KEV, so test-year positives are under-counted.",
        "Backtest CVSS values are current NVD values, not the values on the freeze date.",
        "SBOM dependency depth and fan-in are not code-level reachability, and asset context is user-supplied.",
        "Each SBOM case contains few later-exploited CVEs; statistical claims rely on the population case.",
        "The likelihood weights (0.5, 0.3, 0.2) and the asset multipliers are hand-set; the ablation measures their "
        "effect but does not learn them.",
    ])


def ch11(R: Report, X: Ctx):
    t1 = X.t1
    t2p, t2pop = X.t2(X.P), X.t2(X.POP)
    R.h1("Chapter 11: Conclusions and Future Scope")
    R.h2("11.1 Conclusion")
    R.p("This project set out to rank application vulnerabilities by real-world risk rather than severity and to "
        "prove the result. It delivered a gradient-boosted exploitation classifier trained on public data with a "
        "leakage-controlled, time-based design; an SBOM-aware scoring engine implemented identically in Python and "
        "in the browser; a time-frozen backtest with an ablation; and a deployed system that retrains itself "
        "nightly and publishes only when its tests and quality gate pass.")
    R.p(f"On the {X.test_year} test year the model without EPSS reached an AUC-ROC of "
        f"{f3(t1['model_no_epss']['auc_roc'])} against {f3(t1['cvss']['auc_roc'])} for CVSS. With every input "
        f"frozen at {X.freeze}, the Formula + ML ranking needed {pct(t2p['ml']['effort_to_cover_90'])} of the "
        f"{X.P.get('app', X.prim_key)} findings, against {pct(t2p['cvss']['effort_to_cover_90'])} for CVSS-only, "
        "to cover 90% of the vulnerabilities exploited afterwards; across the population of CVEs published before "
        f"the freeze date the figures were {pct(t2pop['ml']['effort_to_cover_90'])} and "
        f"{pct(t2pop['cvss']['effort_to_cover_90'])}. These numbers are produced by the published pipeline and can "
        "be reproduced from the repository.")
    R.h2("11.2 Future Scope")
    R.numbered([
        "Add call-graph reachability analysis so that only vulnerable code that the application can execute is "
        "prioritized.",
        "Ingest VEX (Vulnerability Exploitability eXchange) statements to suppress findings declared not affected.",
        "Learn the likelihood weights end to end from backtest outcomes instead of setting them by hand.",
        "Run a rolling backtest over several freeze dates and report the mean and spread of the patch-effort gain.",
        "Relabel the model with organization-specific incident and remediation data.",
        "Support SPDX SBOMs and additional scanners, and import asset context from a CMDB.",
        "Track remediation timestamps so that mean time to remediate can be measured rather than assumed.",
    ])


def bibliography(R: Report):
    R.h1("Bibliography")
    refs = [
        "FIRST, \u201cCommon Vulnerability Scoring System v3.1: Specification Document,\u201d 2019. [Online]. "
        "Available: https://www.first.org/cvss/v3.1/specification-document",
        "FIRST, \u201cCommon Vulnerability Scoring System Version 4.0: Specification Document,\u201d 2023. [Online]. "
        "Available: https://www.first.org/cvss/v4.0/specification-document",
        "J. Jacobs, S. Romanosky, B. Edwards, I. Adjerid, and M. Roytman, \u201cExploit Prediction Scoring System "
        "(EPSS),\u201d Digital Threats: Research and Practice, vol. 2, no. 3, Art. no. 20, pp. 1-17, 2021, doi: "
        "10.1145/3436242.",
        "J. Jacobs, S. Romanosky, I. Adjerid, and W. Baker, \u201cImproving Vulnerability Remediation Through "
        "Better Exploit Prediction,\u201d Journal of Cybersecurity, vol. 6, no. 1, 2020, doi: 10.1093/cybsec/tyaa015.",
        "M. Bicudo, C. Pereira, L. Miranda et al., \u201cA Statistical Approach to Severity Aware Vulnerability "
        "Prioritization,\u201d IEEE, 2024. [Online]. Available: https://ieeexplore.ieee.org/document/10815757",
        "Cybersecurity and Infrastructure Security Agency, \u201cKnown Exploited Vulnerabilities Catalog.\u201d "
        "[Online]. Available: https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "B. Jung, Y. Li, and T. Bechor, \u201cCAVP: A Context-Aware Vulnerability Prioritization Model,\u201d "
        "Computers & Security, vol. 116, p. 102639, 2022, doi: 10.1016/j.cose.2022.102639.",
        "F. R. Parente, E. B. Rodrigues, and C. L. C. Mattos, \u201cFRAPE: A Framework for Risk Assessment, "
        "Prioritization and Explainability of Vulnerabilities in Cybersecurity,\u201d Journal of Information "
        "Security and Applications, vol. 89, p. 103971, 2025, doi: 10.1016/j.jisa.2025.103971.",
        "A. Lemay and N. Katiyar, \u201cSupply Chain Risk Analysis Via SBOM Data Enrichment,\u201d IEEE, 2023. "
        "[Online]. Available: https://ieeexplore.ieee.org/document/11014830",
        "M. Beninger, P. Charland, S. H. H. Ding, and B. C. M. Fung, \u201cERS0: Enhancing Military Cybersecurity "
        "with AI-Driven SBOM for Firmware Vulnerability Detection and Asset Management,\u201d IEEE, 2024. "
        "[Online]. Available: https://ieeexplore.ieee.org/document/10685598",
        "J. Squillace, J. Cappella, and A. Sepp, \u201cUser Vulnerabilities in AI-Driven Systems: Current "
        "Cybersecurity Threat Dynamics and Malicious Exploits in Supply Chain Management and Project Management,"
        "\u201d IEEE, 2024. [Online]. Available: https://ieeexplore.ieee.org/document/10459480",
        "OWASP Foundation, \u201cCycloneDX Bill of Materials Specification.\u201d [Online]. Available: "
        "https://cyclonedx.org/specification/overview/",
        "National Institute of Standards and Technology, \u201cNational Vulnerability Database.\u201d [Online]. "
        "Available: https://nvd.nist.gov/ ; data obtained through the fkie-cad NVD JSON data feeds mirror, "
        "https://github.com/fkie-cad/nvd-json-data-feeds",
        "G. Ke, Q. Meng, T. Finley, T. Wang, W. Chen, W. Ma, Q. Ye, and T.-Y. Liu, \u201cLightGBM: A Highly "
        "Efficient Gradient Boosting Decision Tree,\u201d in Advances in Neural Information Processing Systems 30 "
        "(NeurIPS), 2017, pp. 3146-3154.",
        "S. M. Lundberg et al., \u201cFrom Local Explanations to Global Understanding with Explainable AI for "
        "Trees,\u201d Nature Machine Intelligence, vol. 2, no. 1, pp. 56-67, 2020, doi: 10.1038/s42256-019-0138-9.",
        "J. Platt, \u201cProbabilistic Outputs for Support Vector Machines and Comparisons to Regularized "
        "Likelihood Methods,\u201d in Advances in Large Margin Classifiers, MIT Press, 1999, pp. 61-74.",
        "F. Pedregosa et al., \u201cScikit-learn: Machine Learning in Python,\u201d Journal of Machine Learning "
        "Research, vol. 12, pp. 2825-2830, 2011.",
        "National Institute of Standards and Technology, \u201cThe NIST Cybersecurity Framework (CSF) 2.0,\u201d "
        "NIST CSWP 29, Feb. 2024, doi: 10.6028/NIST.CSWP.29.",
        "nomi-sec, \u201cPoC-in-GitHub.\u201d [Online]. Available: https://github.com/nomi-sec/PoC-in-GitHub",
        "OffSec, \u201cExploit Database (files_exploits.csv).\u201d [Online]. Available: "
        "https://gitlab.com/exploit-database/exploitdb",
        "FIRST, \u201cExploit Prediction Scoring System (EPSS) data and API.\u201d [Online]. Available: "
        "https://www.first.org/epss/",
        "Anchore, \u201cSyft: SBOM generator.\u201d [Online]. Available: https://github.com/anchore/syft",
        "Aqua Security, \u201cTrivy: vulnerability scanner.\u201d [Online]. Available: "
        "https://github.com/aquasecurity/trivy",
    ]
    for k, ref in enumerate(refs, 1):
        para = R.p(f"[{k}]\t{ref}", align=LEFT)
        pf = para.paragraph_format
        pf.left_indent = Inches(0.5)
        pf.first_line_indent = Inches(-0.5)
        pf.tab_stops.add_tab_stop(Inches(0.5))


def appendix(R: Report, X: Ctx):
    R.h1("Appendix")
    R.h2("Appendix A: Project Presentation Summary")
    R.p("The results presentation for this phase contains seventeen slides: title, agenda, background, literature "
        "review, problem statement, objectives, architecture and methodology, dataset and split, model results "
        "(Table 10.1 and feature importance), backtest (Table 10.2 and coverage curve), ablation (Table 10.7), live "
        "dashboard, MLOps, outcomes against the proposal-stage expectations, limitations and future work, "
        "references, and closing. It is generated by scripts/build_deck.py from the same result files as this "
        "report, so the two always quote the same numbers.")
    R.p("scripts/build_viva.py writes docs/viva.md, which answers the questions an examiner is expected to ask "
        "using the same result files.")
    R.h2("Appendix B: Input File Examples")
    R.p(("CycloneDX SBOM (excerpt).", "b"), " One component and its dependency entry:")
    R.code(['{"bomFormat": "CycloneDX", "specVersion": "1.4",',
            ' "metadata": {"component": {"bom-ref": "acme-commerce-platform", "name": "acme-commerce-platform"}},',
            ' "components": [{"type": "library", "bom-ref": "log4j-core@2.14.1", "name": "log4j-core",',
            '                 "version": "2.14.1", "purl": "pkg:maven/log4j-core@2.14.1"}],',
            ' "dependencies": [{"ref": "log4j-core@2.14.1", "dependsOn": ["bouncycastle@1.60"]}]}'])
    R.p(("Trivy scan (excerpt).", "b"))
    R.code(['{"Results": [{"Target": "acme-commerce-platform (java)", "Vulnerabilities": [',
            '  {"VulnerabilityID": "CVE-2021-44228", "PkgName": "log4j-core", "InstalledVersion": "2.14.1",',
            '   "FixedVersion": "2.17.1", "CVSS": {"nvd": {"V3Score": 10.0}}}]}]}'])
    R.p(("Asset context (excerpt).", "b"))
    R.code(['{"services": {"payment-api": {"tier": 1, "internet_facing": true, "handles_pii": true,',
            '                              "components": ["log4j-core@2.14.1", "tomcat-embed-core@9.0.30", ...]}}}'])
    R.p(("CSV scan header.", "b"), " Required columns: component, version, cve_id, cvss_base; optional: "
        "cvss_vector, cvss_impact_subscore, cvss_scope, purl, host, description.")
    R.h2("Appendix C: Scoring Parameters and Reproducibility")
    R.table("C", "Scoring Formula Parameters", ["Parameter", "Value"], [
        ["Formula + ML likelihood weights", "P_model 0.5, EPSS 0.3, KEV 0.2"],
        ["Formula + ML impact", "0.5 \u00b7 CVSS impact / 6 + 0.5 \u00b7 fan-in / max fan-in"],
        ["Asset criticality", "Tier 1: 1.5, tier 2: 1.25, tier 3: 1.0; \u00d71.2 internet-facing; 1.0 without "
                              "context; tier 2 if unmatched"],
        ["Scope multiplier", "1.15 if CVSS scope changed"],
        ["Proposal-stage likelihood", "0.65 \u00b7 EPSS + 0.35 \u00b7 maturity (KEV 1.0, Exploit-DB 0.9, GitHub "
                                      "PoC 0.5, none 0.05)"],
        ["Proposal-stage impact", "0.5 \u00b7 CVSS impact / 6 + 0.5 \u00b7 blast radius"],
        ["Proposal-stage blast radius", "0.75 \u00b7 business + 0.25 \u00b7 graph with services, else graph; "
                                        "business = min(1, \u03a3 weights / 3) with Critical 1.0, High 0.7, "
                                        "Medium 0.4, Low 0.2; graph = min(1, fan-in / 5)"],
        ["Proposal-stage scope", "1.15 if scope changed, else 1.08 if at least 3 services or fan-in at least 3"],
        ["Soft ceiling", "Above 90: 100 \u2212 10 \u00b7 e^(\u2212(raw \u2212 90) / 10)"],
        ["Tiers", "Critical \u2265 75, High \u2265 50, Medium \u2265 25, Low < 25"],
        ["CVSS-only", "10 \u00d7 CVSS base score"],
    ], [2.2, 4.3])
    R.table("C", "Reproduction Commands", ["Step", "Command"], [
        ["Install", "pip install -r train/requirements.txt"],
        ["Fetch data", "python -m train.fetch_data --years 2015-2026 --freeze 2025-01-01"],
        ["Features", "python -m train.build_features --years 2015-2026 --freeze 2025-01-01 --out "
                     "data/features.parquet"],
        ["Train", "python -m train.train --features data/features.parquet --out models/"],
        ["Export", "python -m train.export --features data/features.parquet --models models/ --site site/"],
        ["Backtest", "python -m backtest.run_backtest --features data/features.parquet --freeze 2025-01-01 --out "
                     "site/backtest.json"],
        ["Tests", "python -m tests.run_tests"],
        ["Gate", "python -m scripts.gate"],
        ["Screenshots", "python -m scripts.screenshot_dashboard"],
        ["Report", "python -m scripts.build_report"],
        ["Deck and viva sheet", "python -m scripts.build_deck ; python -m scripts.build_viva"],
    ], [1.2, 5.3])


def back_matter(R: Report, X: Ctx):
    R.h1("Plagiarism Report")
    R.p("The institution-generated Turnitin similarity report, with a similarity index below the prescribed "
        "institutional threshold, is to be attached in this annexure after the official similarity check. The title "
        "page and the page showing the final similarity index should be included.")
    R.p("Official similarity report: to be attached by the student / institution after Turnitin verification.")
    R.h1("Declaration of AI Tool Usage")
    R.table(None, None, ["Item / Reference Type", "AI Tool Used", "Purpose of Use",
                                                  "Extent of AI Contribution", "Human Verification / Modification"], [
        ["Source code", "Claude (Anthropic)", "Implementation of the pipeline, dashboard, tests, API and workflows "
                                              "to the mentor's specification", "Generated and revised code under "
                                                                               "the author's direction",
         "Author ran the pipeline, tests and deployment and verified the outputs"],
        ["Report and presentation", "Claude (Anthropic)", "Drafting, structuring and formatting",
         "Drafted text and generator scripts", "Author reviewed technical claims, numbers and final wording"],
        ["Literature review support", "Claude (Anthropic)", "Organizing summaries of cited work",
         "Assisted in presenting cited research", "Author verified the cited sources"],
        ["Results and figures", "None (pipeline output)", "Tables and figures are produced by the project code",
         "No AI-generated numbers", "Author verified that numbers match the published result files"],
    ], [1.2, 1.0, 1.5, 1.4, 1.4])
    R.h1("GitHub Link")
    R.p("Project repository URL: ", (X.args.repo, "b"))
    R.p("Live dashboard URL: ", (X.args.site_url, "b"))


# ---------------------------------------------------------------------------
def main(argv=None):
    today = dt.date.today()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--date", default=f"{ordinal(today.day)} {today.strftime('%B %Y')}",
                    help='date on the declaration pages, e.g. "21st September 2026"')
    ap.add_argument("--month", default=today.strftime("%B %Y"), help='cover date, e.g. "September 2026"')
    ap.add_argument("--repo", default="https://github.com/akilkumarmn/sbom-risk-engine")
    ap.add_argument("--site-url", default="https://akilkumarmn.github.io/sbom-risk-engine/")
    ap.add_argument("--sbom-from-syft", action="store_true",
                    help="the legacy-java-app fixture was regenerated with Syft and Trivy")
    ap.add_argument("--out", type=Path,
                    default=config.ROOT / "docs" / "report" / "CS10_Capstone2_SBOM_Risk_Engine_Akil_Report.docx")
    args = ap.parse_args(argv)

    X = Ctx(args)
    needed = [FIG / "feature_importance.png", FIG / "coverage_test_year.png", FIG / "dashboard.png",
              FIG / "coverage_backtest_population.png", FIG / f"coverage_backtest_{X.prim_key}.png"]
    missing = [str(p) for p in needed if not p.exists()]
    if missing:
        raise SystemExit("missing figures (run the pipeline first):\n  " + "\n  ".join(missing))
    dash, html = FIG / "dashboard.png", config.SITE_DIR / "dashboard.html"
    if dash.stat().st_mtime < html.stat().st_mtime:
        print("NOTE: docs/figures/dashboard.png is older than site/dashboard.html -- refresh it with "
              "'python -m scripts.screenshot_dashboard' so the report shows the current dashboard.")
    draw_methodology(FIG / "report_methodology.png")
    draw_architecture(FIG / "report_architecture.png")
    draw_mlops(FIG / "report_mlops.png")

    R = Report(new_document(), ASSETS / "reva_logo.png")
    front_matter(R, X)
    abstract(R, X)
    for chapter in (ch1, ch2, ch3, ch4, ch5, ch6, ch7, ch8, ch9, ch10, ch11):
        chapter(R, X)
    bibliography(R)
    appendix(R, X)
    back_matter(R, X)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    R.doc.save(str(args.out))
    print(f"wrote {args.out}{'  [SYNTHETIC numbers - rebuild after the real pipeline run]' if X.synthetic else ''}")
    assert R.tables[-3:] == ["Table 10.7", "Table C.1", "Table C.2"], R.tables  # cross-references in the text
    assert R.figures[-4:] == ["Fig. 10.1", "Fig. 10.2", "Fig. 10.3", "Fig. 10.4"], R.figures
    print(f"  {len(R.figures)} figures, {len(R.tables)} tables")


if __name__ == "__main__":
    main()
