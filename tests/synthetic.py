"""Synthetic raw data in the *exact* on-disk formats of the real sources, so
the full pipeline can be exercised offline (CI unit tests, no network).

NOTHING produced from this data is a result. Every artifact built from it is
stamped data_source="synthetic-test-fixture" and the dashboard shows a red
banner if it ever sees one.

Leakage traps planted on purpose (the pipeline must ignore all of them):
  * KEV CVEs carry cisaExploitAdd / cisaRequiredAction fields,
  * KEV CVEs carry a reference to the CISA KEV catalog,
  * KEV CVEs carry a CISA-ADP SSVC block with exploitation="active".
tests/test_pipeline.py asserts none of these reach the feature matrix.
"""
from __future__ import annotations

import csv
import datetime as dt
import gzip
import json
import lzma
import math
from pathlib import Path

import numpy as np

TODAY = dt.date(2026, 9, 21)

ACME = {  # id: (published, base, vector, kev_date or None, gh_poc_days, edb_days, epss_now)
    "CVE-2013-7285": ("2014-05-15", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", None, 400, None, 0.15),
    "CVE-2015-7501": ("2017-11-09", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", None, -500, None, 0.23),
    "CVE-2016-4437": ("2016-06-07", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "2022-01-28", 900, 1200, 0.55),
    "CVE-2017-5638": ("2017-03-11", 10.0, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "2021-11-03", 2, 5, 0.945),
    "CVE-2018-1000613": ("2018-07-09", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", None, None, None, 0.02),
    "CVE-2019-12384": ("2019-06-24", 5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", None, 20, None, 0.04),
    "CVE-2020-1938": ("2020-02-24", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "2025-03-04", 3, 10, 0.65),
    "CVE-2021-29425": ("2021-04-13", 4.8, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", None, None, None, 0.01),
    "CVE-2021-37136": ("2021-09-09", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", None, None, None, 0.05),
    "CVE-2021-44228": ("2021-12-10", 10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "2021-12-10", 0, 3, 0.975),
    "CVE-2022-0778": ("2022-03-15", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", None, 3, None, 0.61),
    "CVE-2022-1471": ("2022-12-01", 8.3, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L", None, 30, None, 0.89),
    "CVE-2022-22965": ("2022-04-01", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "2022-04-04", 0, 20, 0.941),
    "CVE-2022-25845": ("2022-06-10", 8.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "2025-06-10", 15, None, 0.72),
    "CVE-2022-31197": ("2022-08-03", 8.0, "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:H", None, None, None, 0.02),
}

# CVE ids used by backtest/fixtures/legacy-java-app that ACME does not cover.
# Their synthetic metadata (dates, KEV status, EPSS) is fiction, like everything
# else here; only the ids are shared so the fixture correlates in offline runs.
# kev: "before" = listed before the freeze date, "after" = listed after it.
LEGACY = {
    "CVE-2016-3081": "before", "CVE-2018-11776": "before", "CVE-2017-9805": "before",
    "CVE-2021-45046": "before", "CVE-2020-17530": "before",
    "CVE-2023-50164": "after", "CVE-2021-39144": "after", "CVE-2022-42889": "after",
    "CVE-2020-9484": "after", "CVE-2016-1000031": "after",
    "CVE-2019-0230": None, "CVE-2021-31805": None, "CVE-2016-4438": None, "CVE-2016-3092": None,
    "CVE-2023-24998": None, "CVE-2015-6420": None, "CVE-2021-21344": None, "CVE-2019-14379": None,
    "CVE-2020-36518": None, "CVE-2021-45105": None, "CVE-2021-44832": None, "CVE-2022-25857": None,
    "CVE-2021-42392": None, "CVE-2022-23221": None, "CVE-2018-10237": None, "CVE-2020-8908": None,
    "CVE-2020-10683": None, "CVE-2020-13956": None,
}

CWES = [f"CWE-{c}" for c in (79, 89, 20, 787, 125, 22, 352, 434, 78, 416, 94, 502, 287, 862, 918, 611, 400, 119,
                                   200, 269, 306, 77, 190, 476, 863, 798, 601, 732, 295, 327, 770, 668, 284, 120, 427)]
CWE_EFFECT = {"CWE-78": 1.2, "CWE-502": 1.3, "CWE-94": 1.1, "CWE-287": 0.9, "CWE-918": 0.8, "CWE-22": 0.6,
              "CWE-79": -1.0, "CWE-352": -0.6}


def _sig(x):
    return 1 / (1 + math.exp(-x))


def generate(out_dir: Path, per_year: int = 900, seed: int = 7) -> dict:
    rng = np.random.default_rng(seed)
    out_dir = Path(out_dir)
    (out_dir / "nvd").mkdir(parents=True, exist_ok=True)
    poc_dir = out_dir / "poc-in-github"
    vendors = [f"vendor{i:03d}" for i in range(250)]
    vendor_effect = {v: (1.6 if i % 25 == 0 else 0.0) + rng.normal(0, 0.3) for i, v in enumerate(vendors)}
    vendor_p = 1 / np.arange(1, len(vendors) + 1) ** 0.9
    vendor_p /= vendor_p.sum()

    kev_rows, epss_now, epss_t, gh, edb = [], {}, {}, {}, {}
    freeze = dt.date(2025, 1, 1)
    for year in range(2013, 2027):
        n = per_year if 2019 <= year <= 2025 else (per_year // 6 if year < 2026 else per_year // 3)
        items = []
        for i in range(n):
            cid = f"CVE-{year}-{10000 + i}"
            pub = dt.date(year, 1, 1) + dt.timedelta(days=int(rng.integers(0, 365)))
            if pub > TODAY - dt.timedelta(days=5):
                pub = TODAY - dt.timedelta(days=5)
            av = rng.choice(list("NALP"), p=[0.68, 0.05, 0.24, 0.03])
            ac = rng.choice(list("LH"), p=[0.82, 0.18])
            pr = rng.choice(list("NLH"), p=[0.5, 0.38, 0.12])
            ui = rng.choice(list("NR"), p=[0.62, 0.38])
            sc = rng.choice(list("UC"), p=[0.86, 0.14])
            c, i_, a = (rng.choice(list("HLN"), p=[0.55, 0.25, 0.2]) for _ in range(3))
            vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{sc}/C:{c}/I:{i_}/A:{a}"
            cwe = rng.choice(CWES)
            vendor = vendors[int(rng.choice(len(vendors), p=vendor_p))]
            rce = rng.random() < (0.35 if cwe in ("CWE-78", "CWE-94", "CWE-502") else 0.08)
            unauth = rng.random() < (0.25 if pr == "N" else 0.03)
            deser = cwe == "CWE-502" or rng.random() < 0.01
            exploitable = (av == "N") + (pr == "N") + (ui == "N")
            poc_gh = rng.random() < 0.04 + 0.03 * exploitable + 0.1 * rce
            poc_edb = rng.random() < 0.01 + 0.02 * rce
            logit = (-6.3 + 1.1 * (av == "N") + 0.9 * (pr == "N") + 0.7 * (ui == "N") + 1.4 * rce + 0.9 * unauth
                     + 0.8 * deser + 1.5 * poc_gh + 0.8 * poc_edb + vendor_effect[vendor]
                     + CWE_EFFECT.get(cwe, 0.0) + rng.normal(0, 0.6))
            kev_date = None
            if rng.random() < _sig(logit):
                kd = pub + dt.timedelta(days=int(rng.exponential(260)))
                if kd <= TODAY:
                    kev_date = kd
            gh_first = (pub + dt.timedelta(days=int(rng.integers(-20, 60)))) if poc_gh else None
            edb_first = (pub + dt.timedelta(days=int(rng.integers(0, 90)))) if poc_edb else None
            # a PoC written *after* KEV listing is a common real pattern (leak trap for window features)
            if kev_date and not poc_gh and rng.random() < 0.5:
                gh_first = kev_date + dt.timedelta(days=int(rng.integers(1, 30)))
            desc = _desc(rng, rce, unauth, deser, cwe, vendor)
            no_vector = year >= 2024 and rng.random() < 0.08
            items.append(_nvd_item(cid, pub, vector, desc, cwe, vendor, kev_date, rng, no_vector, poc_edb))
            if kev_date:
                kev_rows.append((cid, kev_date, vendor))
            base_e = _sig(logit + 1.0) * 0.6
            epss_now[cid] = min(0.97, base_e + (0.4 if kev_date else 0) * rng.random())
            if pub < freeze:
                epss_t[cid] = min(0.97, base_e + (0.4 if kev_date and kev_date <= freeze else 0) * rng.random())
            if gh_first:
                gh[cid] = gh_first
            if edb_first:
                edb[cid] = edb_first
        lrng = np.random.default_rng(1000 + year)
        for cid, when in LEGACY.items():
            if int(cid.split("-")[1]) != year:
                continue
            pub = dt.date(year, 1, 1) + dt.timedelta(days=int(lrng.integers(0, 330)))
            if pub >= freeze:
                pub = freeze - dt.timedelta(days=30)
            vec = str(lrng.choice(["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                   "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                   "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"]))
            kdd = None
            if when == "before":
                kdd = min(freeze - dt.timedelta(days=10), pub + dt.timedelta(days=int(lrng.integers(5, 400))))
            elif when == "after":
                kdd = freeze + dt.timedelta(days=int(lrng.integers(20, 300)))
            rce = when is not None or lrng.random() < 0.3
            desc = f"Synthetic record for {cid}: " + ("remote code execution" if rce else "denial of service") + " in library."
            has_edb = when is not None and lrng.random() < 0.5
            items.append(_nvd_item(cid, pub, vec, desc, "CWE-502" if rce else "CWE-400", "apache", kdd, lrng, False, has_edb))
            if kdd:
                kev_rows.append((cid, kdd, "apache"))
            e = float(lrng.uniform(0.2, 0.7) if when == "after" else lrng.uniform(0.3, 0.95) if when else lrng.uniform(0.001, 0.08))
            epss_t[cid] = e
            epss_now[cid] = min(0.97, e + (0.3 if when == "after" else 0.0))
            if when is not None and lrng.random() < 0.6:
                gh[cid] = pub + dt.timedelta(days=int(lrng.integers(0, 25)))
            if has_edb:
                edb[cid] = pub + dt.timedelta(days=int(lrng.integers(0, 60)))
        if year in {int(k.split("-")[1]) for k in ACME}:
            for cid, (pub_s, base, vec, kd, ghd, edd, ep) in ACME.items():
                if int(cid.split("-")[1]) != year:
                    continue
                pub = dt.date.fromisoformat(pub_s)
                kdd = dt.date.fromisoformat(kd) if kd else None
                items.append(_nvd_item(cid, pub, vec, f"Synthetic record for {cid}: remote code execution in library.",
                                       "CWE-502", "apache", kdd, rng, False, edd is not None, base=base))
                if kdd:
                    kev_rows.append((cid, kdd, "apache"))
                epss_now[cid] = ep
                epss_t[cid] = ep * (0.5 if kdd and kdd > freeze else 1.0)
                if ghd is not None:
                    gh[cid] = pub + dt.timedelta(days=ghd)
                if edd is not None:
                    edb[cid] = pub + dt.timedelta(days=edd)
        # one rejected record per year (must be dropped)
        items.append({"id": f"CVE-{year}-99999", "published": f"{year}-06-01T00:00:00.000", "vulnStatus": "Rejected",
                      "descriptions": [{"lang": "en", "value": "Rejected reason: duplicate."}], "metrics": {},
                      "references": []})
        doc = {"timestamp": "2026-09-21T00:00:00", "cve_count": len(items), "feed_name": f"CVE-{year}",
               "source": "synthetic", "cve_items": items}
        with lzma.open(out_dir / "nvd" / f"CVE-{year}.json.xz", "wt", encoding="utf-8") as f:
            json.dump(doc, f)

    kev = {"title": "CISA Catalog of Known Exploited Vulnerabilities", "catalogVersion": "2026.09.19",
           "dateReleased": "2026-09-19T15:00:00.0000Z", "count": len(kev_rows),
           "vulnerabilities": [{"cveID": c, "vendorProject": v, "product": "p", "vulnerabilityName": "x",
                                "dateAdded": d.isoformat(), "shortDescription": "", "requiredAction": "",
                                "dueDate": (d + dt.timedelta(days=21)).isoformat(),
                                "knownRansomwareCampaignUse": "Unknown", "notes": "", "cwes": []}
                               for c, d, v in sorted(kev_rows, key=lambda r: r[1])]}
    (out_dir / "kev.json").write_text(json.dumps(kev))
    _write_epss(out_dir / "epss_current.csv.gz", epss_now, "2026-09-20")
    _write_epss(out_dir / "epss_2025-01-01.csv.gz", epss_t, "2025-01-01")
    for cid, d in gh.items():
        year = cid.split("-")[1]
        (poc_dir / year).mkdir(parents=True, exist_ok=True)
        repos = [{"id": 1, "name": "poc", "full_name": f"someone/{cid}", "html_url": f"https://github.com/someone/{cid}",
                  "fork": False, "created_at": f"{d.isoformat()}T10:00:00Z", "stargazers_count": 3}]
        (poc_dir / year / f"{cid}.json").write_text(json.dumps(repos))
    with open(out_dir / "exploitdb.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id", "file", "description", "date_published", "author", "type", "platform", "port",
                    "date_added", "date_updated", "verified", "codes", "tags", "aliases", "screenshot_url",
                    "application_url", "source_url"])
        for k, (cid, d) in enumerate(edb.items()):
            w.writerow([k + 1, f"exploits/x/{k}.py", "Synthetic exploit", d.isoformat(), "anon", "remote", "linux",
                        "", d.isoformat(), d.isoformat(), 1, f"{cid};OSVDB-{k}", "", "", "", "", ""])
    return {"kev": len(kev_rows), "epss": len(epss_now), "poc_github": len(gh), "exploitdb": len(edb)}


def _desc(rng, rce, unauth, deser, cwe, vendor):
    parts = [f"A vulnerability in {vendor} product"]
    if unauth:
        parts.append("allows an unauthenticated remote attacker")
    else:
        parts.append("allows an authenticated user")
    if rce:
        parts.append("to execute arbitrary code")
    elif cwe == "CWE-79":
        parts.append("to inject arbitrary web script via a crafted parameter")
    else:
        parts.append("to cause unexpected behaviour")
    if deser:
        parts.append("through unsafe deserialization of untrusted data")
    if rng.random() < 0.1:
        parts.append(", which is a server-side request forgery (SSRF) issue")
    return " ".join(parts) + "."


def _nvd_item(cid, pub, vector, desc, cwe, vendor, kev_date, rng, no_vector, has_edb, base=None):
    from engine.cvss import impact_subscore, parse_vector
    p = parse_vector(vector)
    impact = impact_subscore(p)
    if base is None:
        base = min(10.0, round(impact + rng.uniform(1.5, 3.9), 1)) if impact > 0 else 0.0
    refs = [{"url": f"https://{vendor}.example.com/advisory/{cid}", "source": "cna", "tags": ["Vendor Advisory"]},
            {"url": f"https://{vendor}.example.com/advisory/{cid}", "source": "nvd", "tags": ["Patch"]}]
    if has_edb:
        refs.append({"url": f"https://www.exploit-db.com/exploits/{cid[-5:]}", "source": "nvd", "tags": ["Exploit", "Third Party Advisory"]})
    if rng.random() < 0.2:
        refs.append({"url": f"https://github.com/{vendor}/repo/commit/abc", "source": "nvd", "tags": ["Patch"]})
    item = {
        "id": cid, "sourceIdentifier": "cna@example.com",
        "published": f"{pub.isoformat()}T12:00:00.000", "lastModified": "2026-09-01T00:00:00.000",
        "vulnStatus": "Analyzed", "cveTags": [],
        "descriptions": [{"lang": "en", "value": desc}, {"lang": "es", "value": "Descripción sintética."}],
        "metrics": {}, "weaknesses": [{"source": "nvd@nist.gov", "type": "Primary",
                                        "description": [{"lang": "en", "value": cwe}]}],
        "references": refs,
    }
    if not no_vector:
        item["metrics"]["cvssMetricV31"] = [
            {"source": "cna@example.com", "type": "Secondary",
             "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", "baseScore": 1.8},
             "exploitabilityScore": 0.2, "impactScore": 1.4},
            {"source": "nvd@nist.gov", "type": "Primary",
             "cvssData": {"version": vector.split("/")[0].split(":")[1], "vectorString": vector, "baseScore": base},
             "exploitabilityScore": 3.9, "impactScore": impact}]
    if int(cid.split("-")[1]) < 2016:
        item["metrics"]["cvssMetricV2"] = [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"baseScore": 7.5}}]
    if rng.random() < 0.85:
        item["configurations"] = [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [
            {"vulnerable": True, "criteria": f"cpe:2.3:a:{vendor}:product_{cid[-2:]}:*:*:*:*:*:*:*:*",
             "matchCriteriaId": "X"}]}]}]
    else:
        item["affected"] = [{"source": "cna", "affectedData": [{"vendor": vendor, "product": "x",
                             "cpes": [f"cpe:2.3:a:{vendor}:product_{cid[-2:]}:*:*:*:*:*:*:*:*"]}]}]
    if kev_date:  # ---- leakage traps ----
        item["cisaExploitAdd"] = kev_date.isoformat()
        item["cisaActionDue"] = (kev_date + dt.timedelta(days=21)).isoformat()
        item["cisaRequiredAction"] = "Apply updates per vendor instructions."
        item["references"].append({"url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search=" + cid,
                                   "source": "nvd", "tags": ["US Government Resource"]})
        item["metrics"]["ssvcV203"] = [{"source": "cisa", "ssvcData": {"options": [{"exploitation": "active"}]}}]
    return item


def _write_epss(path: Path, scores: dict, date: str):
    with gzip.open(path, "wt", encoding="utf-8") as f:
        f.write(f"#model_version:v2025.03.14,score_date:{date}T12:55:00Z\n")
        f.write("cve,epss,percentile\n")
        vals = sorted(scores.values())
        for cid, e in scores.items():
            pct = (np.searchsorted(vals, e, side="right")) / len(vals)
            f.write(f"{cid},{e:.5f},{pct:.5f}\n")


if __name__ == "__main__":
    import sys
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "data/synthetic_raw")
    print(generate(target))
