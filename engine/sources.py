"""Download and parse the five public sources. Every loader returns plain
pandas objects so the rest of the pipeline never touches raw formats."""
from __future__ import annotations

import csv
import gzip
import io
import json
import lzma
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pandas as pd

from . import config
from .cvss import impact_subscore, parse_vector

_UA = "Mozilla/5.0 (X11; Linux x86_64) sbom-risk-engine/1.0 (+https://github.com)"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


# ---------------------------------------------------------------------------
# Download helpers
# ---------------------------------------------------------------------------
def download(url: str, dest: Path, retries: int = 3, timeout: int = 300) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    last_err: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": _UA})
            with urllib.request.urlopen(req, timeout=timeout) as r, open(tmp, "wb") as f:
                shutil.copyfileobj(r, f, length=1 << 20)
            tmp.replace(dest)
            return dest
        except Exception as e:  # noqa: BLE001 - report and retry any network error
            last_err = e
            print(f"  download attempt {attempt}/{retries} failed for {url}: {e}", file=sys.stderr)
            time.sleep(3 * attempt)
    raise RuntimeError(f"Could not download {url}: {last_err}")


def git_shallow_clone(repo: str, dest: Path) -> Path:
    if dest.exists():
        shutil.rmtree(dest)
    subprocess.run(["git", "clone", "--depth", "1", "--quiet", repo, str(dest)], check=True)
    return dest


# ---------------------------------------------------------------------------
# NVD (fkie-cad release feed: {"cve_items": [<NVD API 2.0 CVE object>, ...]})
# ---------------------------------------------------------------------------
def _open_json(path: Path):
    if path.suffix == ".xz":
        with lzma.open(path, "rt", encoding="utf-8") as f:
            return json.load(f)
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as f:
            return json.load(f)
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _iter_items(doc):
    if isinstance(doc, list):
        items = doc
    else:
        items = doc.get("cve_items") or doc.get("vulnerabilities") or doc.get("CVE_Items") or []
    for it in items:
        if isinstance(it, dict) and "cve" in it and "id" not in it:
            it = it["cve"]  # NVD API 2.0 wraps each record as {"cve": {...}}
        if isinstance(it, dict) and it.get("id"):
            yield it


def _pick_cvss3(metrics: dict) -> dict | None:
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        primary = [e for e in entries if e.get("type") == "Primary"]
        return (primary or entries)[0]
    return None


def _pick_cwe(weaknesses: list) -> str:
    """Primary NVD CWE if present, else the first CNA CWE; 'noinfo' otherwise."""
    ordered = sorted(weaknesses or [], key=lambda w: 0 if w.get("type") == "Primary" else 1)
    for w in ordered:
        for d in w.get("description", []):
            v = (d.get("value") or "").strip()
            if v.startswith("CWE-"):
                return v
    return "noinfo"


def _vendor_product(item: dict) -> tuple[str, str]:
    def from_cpe(cpe: str):
        parts = cpe.split(":")
        if len(parts) > 4 and parts[3] and parts[4]:
            return parts[3].lower(), parts[4].lower()
        return None

    for conf in item.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if m.get("vulnerable") and m.get("criteria"):
                    vp = from_cpe(m["criteria"])
                    if vp:
                        return vp
    # Not-yet-analysed CVEs (NVD backlog) often carry CPEs only in "affected".
    for aff in item.get("affected") or []:
        for ad in aff.get("affectedData") or []:
            for cpe in ad.get("cpes") or []:
                vp = from_cpe(cpe)
                if vp:
                    return vp
    return "unknown", "unknown"


def _references(item: dict) -> dict:
    by_url: dict[str, set] = {}
    for ref in item.get("references") or []:
        url = (ref.get("url") or "").strip()
        if not url:
            continue
        low = url.lower()
        if any(m in low for m in config.LEAKY_REFERENCE_MARKERS):
            continue  # KEV-catalog links are the label itself
        by_url.setdefault(low, set()).update(ref.get("tags") or [])
    out = {
        "ref_total": len(by_url),
        "ref_exploit": sum("Exploit" in t for t in by_url.values()),
        "ref_patch": sum("Patch" in t for t in by_url.values()),
        "ref_vendor_advisory": sum("Vendor Advisory" in t for t in by_url.values()),
    }
    for col, domains in config.EXPLOIT_DOMAINS.items():
        out[col] = int(any(any(f"//{d}" in u or f".{d}" in u for d in domains) for u in by_url))
    return out


def extract_cve(item: dict) -> dict | None:
    """One NVD record -> one flat row. Deliberately ignores cisaExploitAdd,
    cisaActionDue, cisaRequiredAction, cisaVulnerabilityName and CISA SSVC
    'exploitation' values: all of them are downstream of KEV and would leak
    the label into the features."""
    status = (item.get("vulnStatus") or "").lower()
    descs = item.get("descriptions") or []
    desc = next((d.get("value", "") for d in descs if d.get("lang") == "en"), "")
    if status == "rejected" or desc.startswith("** REJECT **"):
        return None
    metrics = item.get("metrics") or {}
    m3 = _pick_cvss3(metrics)
    vector = base = impact = None
    if m3:
        cd = m3.get("cvssData") or {}
        vector = cd.get("vectorString")
        base = cd.get("baseScore")
        impact = m3.get("impactScore")
    parsed = parse_vector(vector)
    if impact is None and parsed:
        impact = impact_subscore(parsed)
    cvss2 = None
    for e in metrics.get("cvssMetricV2") or []:
        cvss2 = (e.get("cvssData") or {}).get("baseScore")
        break
    vendor, product = _vendor_product(item)
    row = {
        "cve": item["id"],
        "published": (item.get("published") or "")[:10],
        "description": desc,
        "cvss_vector": vector if parsed else None,
        "cvss_base": float(base) if base is not None and parsed else None,
        "cvss_impact": float(impact) if impact is not None and parsed else None,
        "cvss2_base": float(cvss2) if cvss2 is not None else None,
        "cwe": _pick_cwe(item.get("weaknesses") or []),
        "vendor": vendor,
        "product": f"{vendor}:{product}",
    }
    row.update(_references(item))
    return row


def load_nvd(nvd_dir: Path, years: list[int]) -> pd.DataFrame:
    frames = []
    for y in years:
        path = None
        for cand in (f"CVE-{y}.json.xz", f"CVE-{y}.json.gz", f"CVE-{y}.json"):
            if (nvd_dir / cand).exists():
                path = nvd_dir / cand
                break
        if path is None:
            print(f"  [nvd] no feed for {y} in {nvd_dir}, skipping", file=sys.stderr)
            continue
        rows = [r for r in (extract_cve(it) for it in _iter_items(_open_json(path))) if r]
        print(f"  [nvd] {path.name}: {len(rows):,} CVEs")
        frames.append(pd.DataFrame(rows))
    if not frames:
        raise RuntimeError(f"No NVD feeds found in {nvd_dir}")
    df = pd.concat(frames, ignore_index=True).drop_duplicates("cve", keep="last")
    df["published"] = pd.to_datetime(df["published"], errors="coerce")
    return df.dropna(subset=["published"]).reset_index(drop=True)


# ---------------------------------------------------------------------------
# CISA KEV
# ---------------------------------------------------------------------------
def load_kev(path: Path) -> tuple[pd.DataFrame, dict]:
    doc = _open_json(path)
    rows = [{"cve": v["cveID"].strip(), "kev_date_added": v.get("dateAdded")}
            for v in doc.get("vulnerabilities", []) if v.get("cveID")]
    df = pd.DataFrame(rows)
    df["kev_date_added"] = pd.to_datetime(df["kev_date_added"], errors="coerce")
    df = df.sort_values("kev_date_added").drop_duplicates("cve", keep="first")
    meta = {"catalogVersion": doc.get("catalogVersion"), "dateReleased": doc.get("dateReleased"),
            "count": int(len(df))}
    return df.reset_index(drop=True), meta


# ---------------------------------------------------------------------------
# FIRST EPSS  (first line is a '#model_version:...,score_date:...' comment)
# ---------------------------------------------------------------------------
def load_epss(path: Path) -> tuple[pd.DataFrame, dict]:
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as f:
        first = f.readline()
        meta = {}
        if first.startswith("#"):
            for kv in first.lstrip("#").strip().split(","):
                if ":" in kv:
                    k, v = kv.split(":", 1)
                    meta[k.strip()] = v.strip()
            body = f.read()
        else:
            body = first + f.read()
    df = pd.read_csv(io.StringIO(body), usecols=["cve", "epss", "percentile"])
    df["epss"] = pd.to_numeric(df["epss"], errors="coerce").fillna(0.0)
    df["percentile"] = pd.to_numeric(df["percentile"], errors="coerce").fillna(0.0)
    return df.drop_duplicates("cve"), meta


# ---------------------------------------------------------------------------
# Public PoC sources -> first date a public exploit/PoC appeared
# ---------------------------------------------------------------------------
def load_poc_github(repo_dir: Path) -> pd.Series:
    """nomi-sec/PoC-in-GitHub: <year>/<CVE-ID>.json, each a list of GitHub
    repositories with 'created_at'. Returns earliest created_at per CVE."""
    first: dict[str, pd.Timestamp] = {}
    for p in repo_dir.glob("*/CVE-*.json"):
        try:
            repos = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        dates = [r.get("created_at") for r in repos if isinstance(r, dict) and r.get("created_at")]
        if dates:
            first[p.stem] = pd.to_datetime(min(dates), utc=True).tz_localize(None)
    return pd.Series(first, name="poc_github_first", dtype="datetime64[ns]")


def load_exploitdb(path: Path) -> pd.Series:
    first: dict[str, pd.Timestamp] = {}
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        for row in csv.DictReader(f):
            date = pd.to_datetime(row.get("date_published") or row.get("date_added"), errors="coerce")
            if pd.isna(date):
                continue
            for cve in CVE_RE.findall(row.get("codes") or ""):
                if cve not in first or date < first[cve]:
                    first[cve] = date
    return pd.Series(first, name="poc_exploitdb_first", dtype="datetime64[ns]")
