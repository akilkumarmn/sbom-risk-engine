"""Build a backtest fixture that actually contains later-exploited CVEs.

The two existing SBOM cases have no CVE that CISA added to KEV after the freeze
date, so the SBOM backtest has nothing to measure. This script finds the CVEs
that *were* added afterwards, asks OSV which package versions they affect, and
writes dependency manifests pinned to those versions. Syft and Trivy then
produce a genuine SBOM and scan from the manifests - the fixture is real
scanner output, not hand-written.

    # 1. pick the CVEs and write the manifests (needs the internet, no API key)
    python -m scripts.make_backtest_fixture --freeze 2025-01-01

    # 2. run the real tools over them (PowerShell on Windows)
    powershell -ExecutionPolicy Bypass -File scripts\\build_kev_fixture.ps1
    bash scripts/build_kev_fixture.sh          # macOS / Linux / Git Bash

    # 3. check how many target CVEs Trivy actually reports
    python -m scripts.make_backtest_fixture --verify

Step 2 needs syft and trivy (or Docker). Everything it produces lands in
backtest/fixtures/kev-2025-app/.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from engine import config
from engine.io_utils import read_table

OSV_VULN = "https://api.osv.dev/v1/vulns/"
OSV_ZIP = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
ECOSYSTEMS = ("Maven", "npm", "PyPI")
HEADERS = {"User-Agent": "sbom-risk-engine/1.0 (capstone project fixture builder)"}


def fetch_archive(eco: str, cache: Path) -> Path:
    """OSV publishes one zip of every advisory per ecosystem. Using it avoids
    461 API calls and works for CVE ids, which OSV stores as *aliases* of its
    own advisory ids (GHSA-..., PYSEC-...) rather than as primary ids."""
    cache.mkdir(parents=True, exist_ok=True)
    dest = cache / f"{eco}-all.zip"
    if dest.exists() and dest.stat().st_size > 1000:
        print(f"  {eco}: using cached {dest.name} ({dest.stat().st_size / 1e6:.0f} MB)")
        return dest
    url = OSV_ZIP.format(eco=eco)
    print(f"  {eco}: downloading {url}")
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=300) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f)
    print(f"  {eco}: {dest.stat().st_size / 1e6:.0f} MB")
    return dest


def scan_archive(path: Path, eco: str, targets: set[str], freeze: str | None = None,
                 published: dict | None = None) -> dict[tuple, list]:
    """{(ecosystem, package, version): [cve, ...]} for advisories whose aliases
    include one of the target CVEs.

    A CVE only belongs in the fixture if it was published *before* the freeze
    date - a scan taken on that date cannot contain anything newer, and the
    backtest drops such findings. The publication date comes from the feature
    table when it is available, otherwise from the OSV advisory.
    """
    found: dict[tuple, list] = {}
    late = 0
    with zipfile.ZipFile(path) as z:
        for name in z.namelist():
            if not name.endswith(".json"):
                continue
            try:
                adv = json.loads(z.read(name))
            except Exception:  # noqa: BLE001
                continue
            hits = targets & ({adv.get("id", "")} | set(adv.get("aliases") or []))
            if not hits:
                continue
            if freeze:
                keep = set()
                for cve in hits:
                    when = (published or {}).get(cve) or (adv.get("published") or "")[:10]
                    if when and when >= freeze:
                        late += 1
                        continue
                    keep.add(cve)
                hits = keep
                if not hits:
                    continue
            for aff in adv.get("affected", []):
                pkg = aff.get("package", {})
                if (pkg.get("ecosystem") or "").split(":")[0] != eco or not pkg.get("name"):
                    continue
                ver = pick_version(aff)
                if not ver:
                    continue
                found.setdefault((eco, pkg["name"], ver), []).extend(sorted(hits))
                break
    if late:
        print(f"  {eco}: {late} target CVEs skipped (published on or after {freeze}; a scan taken then could not "
              "contain them)")
    return found


def osv(cve: str, timeout=20):
    """Direct lookup, used only by --single."""
    try:
        req = urllib.request.Request(OSV_VULN + cve, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except Exception:  # noqa: BLE001
        return None


def _vsort(v: str):
    """Rough version ordering: numeric parts first, then the rest."""
    parts = re.split(r"[.\-+_]", v)
    return [(0, int(p)) if p.isdigit() else (1, p) for p in parts]


def pick_version(affected: dict) -> str | None:
    """Highest version OSV lists as affected, else the 'introduced' bound."""
    versions = [v for v in affected.get("versions", []) if v and not re.search(r"(alpha|beta|rc|snapshot|dev)", v, re.I)]
    if versions:
        try:
            return sorted(versions, key=_vsort)[-1]
        except Exception:  # noqa: BLE001
            return versions[-1]
    for rng in affected.get("ranges", []):
        for ev in rng.get("events", []):
            if ev.get("introduced") and ev["introduced"] != "0":
                return ev["introduced"]
    return None


def kev_after(freeze, kev_path: Path) -> list[str]:
    """CVE ids that CISA added to KEV after the freeze date."""
    kev = json.loads(kev_path.read_text(encoding="utf-8-sig"))
    added = kev.get("cves") or {v["cveID"]: v["dateAdded"] for v in kev.get("vulnerabilities", [])}
    return sorted(c for c, d in added.items() if d and str(d)[:10] > freeze)


def published_from_features(features: Path) -> dict | None:
    """Published dates from the feature table, or None if it cannot be read.

    The feature table lives under data/ and is not part of the repository, so it
    may be missing or damaged on a fresh checkout; OSV carries the same date.
    """
    try:
        df = read_table(features)
        return {c: str(p)[:10] for c, p in zip(df["cve"], df["published"])}
    except Exception as e:  # noqa: BLE001
        print(f"note: could not read {features} ({type(e).__name__}); using OSV publication dates instead")
        return None


def write_manifests(chosen: dict[str, list], out: Path, freeze: str):
    src = out / "src"
    src.mkdir(parents=True, exist_ok=True)
    maven = [(n, v, c) for (eco, n, v), c in chosen.items() if eco == "Maven"]
    npm = [(n, v, c) for (eco, n, v), c in chosen.items() if eco == "npm"]
    pypi = [(n, v, c) for (eco, n, v), c in chosen.items() if eco == "PyPI"]
    if maven:
        deps = []
        for name, ver, _ in sorted(maven):
            gid, _, aid = name.partition(":")
            deps.append(f"    <dependency>\n      <groupId>{gid}</groupId>\n      <artifactId>{aid or gid}"
                        f"</artifactId>\n      <version>{ver}</version>\n    </dependency>")
        (src / "pom.xml").write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
            "  <modelVersion>4.0.0</modelVersion>\n"
            "  <groupId>edu.reva.race</groupId>\n  <artifactId>kev-2025-app</artifactId>\n"
            "  <version>1.0.0</version>\n  <packaging>jar</packaging>\n"
            f"  <!-- Dependency versions pinned to CVEs that CISA added to KEV after {freeze};\n"
            "       generated by scripts/make_backtest_fixture.py from OSV affected-version data. -->\n"
            "  <dependencies>\n" + "\n".join(deps) + "\n  </dependencies>\n</project>\n", encoding="utf-8")
    if npm:
        (src / "package.json").write_text(json.dumps({
            "name": "kev-2025-app", "version": "1.0.0", "private": True,
            "description": f"Dependencies pinned to CVEs added to CISA KEV after {freeze} (backtest fixture)",
            "dependencies": {n: v for n, v, _ in sorted(npm)}}, indent=2) + "\n", encoding="utf-8")
    if pypi:
        (src / "requirements.txt").write_text(
            f"# Pinned to CVEs added to CISA KEV after {freeze} (backtest fixture)\n"
            + "".join(f"{n}=={v}\n" for n, v, _ in sorted(pypi)), encoding="utf-8")
    ctx = {"_comment": "Illustrative asset context for the KEV-2025 backtest fixture.",
           "services": {"public-api": {"tier": 1, "internet_facing": True, "handles_pii": True,
                                       "components": ["kev-2025-app"]}}}
    (out / "asset-context.json").write_text(json.dumps(ctx, indent=2) + "\n", encoding="utf-8")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--freeze", default=config.FREEZE_DATE.isoformat())
    ap.add_argument("--kev", type=Path, default=config.SITE_DIR / "data" / "kev.json")
    ap.add_argument("--features", type=Path, default=config.DATA_DIR / "features.parquet")
    ap.add_argument("--out", type=Path, default=config.ROOT / "backtest" / "fixtures" / "kev-2025-app")
    ap.add_argument("--limit", type=int, default=0, help="stop after N candidate CVEs (0 = all)")
    ap.add_argument("--max-packages", type=int, default=60)
    ap.add_argument("--ecosystems", default=",".join(ECOSYSTEMS), help="OSV ecosystems to search")
    ap.add_argument("--cache", type=Path, default=config.DATA_DIR / "osv", help="where the OSV archives are kept")
    ap.add_argument("--verify", action="store_true", help="check an existing trivy.json against the target CVEs")
    args = ap.parse_args(argv)

    if args.verify:
        targets = json.loads((args.out / "targets.json").read_text(encoding="utf-8-sig"))
        scan = json.loads((args.out / "trivy.json").read_text(encoding="utf-8-sig"))
        found = {v["VulnerabilityID"] for r in scan.get("Results", []) for v in (r.get("Vulnerabilities") or [])}
        want = set(targets["cves"])
        hit = sorted(want & found)
        print(f"target CVEs: {len(want)}  reported by Trivy: {len(hit)}")
        print("  covered : " + ", ".join(hit[:20]) + (" ..." if len(hit) > 20 else ""))
        missing = sorted(want - found)
        if missing:
            print("  missing : " + ", ".join(missing[:20]) + (" ..." if len(missing) > 20 else ""))
            print("  (a miss usually means the pinned version is not the affected one, or Trivy's database "
                  "disagrees with OSV; drop those lines from the manifest or pin another version)")
        print(f"\nScan also reports {len(found - want)} other CVEs - that is fine and realistic: they become the "
              "negatives of the backtest.")
        return

    candidates = kev_after(args.freeze, args.kev)
    pub = published_from_features(args.features)
    if args.limit:
        candidates = candidates[:args.limit]
    targets = set(candidates)
    print(f"{len(targets)} CVEs were added to KEV after {args.freeze}; keeping only those published before "
          f"it ({'NVD dates' if pub else 'OSV advisory dates'}).")
    print("matching them against the OSV advisory archives (CVE ids are aliases there, so the whole archive is "
          "searched):")
    chosen: dict[tuple, list] = {}
    for eco in args.ecosystems.split(","):
        eco = eco.strip()
        if not eco:
            continue
        try:
            zip_path = fetch_archive(eco, args.cache)
        except Exception as e:  # noqa: BLE001
            print(f"  ! {eco}: download failed ({e}); skipping")
            continue
        hits = scan_archive(zip_path, eco, targets, args.freeze, pub)
        print(f"  {eco}: {len(hits)} package versions carrying "
              f"{len({c for cs in hits.values() for c in cs})} of the target CVEs")
        chosen.update(hits)
    if len(chosen) > args.max_packages:
        top = sorted(chosen.items(), key=lambda kv: -len(kv[1]))[:args.max_packages]
        chosen = dict(top)
    covered = sorted({c for cs in chosen.values() for c in cs})
    args.out.mkdir(parents=True, exist_ok=True)
    write_manifests(chosen, args.out, args.freeze)
    (args.out / "targets.json").write_text(json.dumps({
        "freeze": args.freeze, "generated_from": "OSV affected-version data",
        "candidates": len(targets), "packages": [f"{e}:{n}@{v}" for (e, n, v) in chosen],
        "cves": covered}, indent=2) + "\n", encoding="utf-8")
    print(f"\n{len(covered)} target CVEs mapped onto {len(chosen)} packages -> {args.out / 'src'}")
    if len(covered) < 8:
        print("few usable CVEs at this freeze date. Most KEV entries are operating systems, appliances and "
              "firmware, and anything published after the freeze date cannot appear in the scan. Try a wider "
              "search or an earlier freeze, e.g.\n"
              "  python -m scripts.make_backtest_fixture --freeze 2024-01-01 "
              "--ecosystems Maven,PyPI,npm,Go,NuGet,RubyGems,Packagist,crates.io")
    print("next: run syft + trivy over the manifests (bash scripts/build_kev_fixture.sh), then\n"
          "      python -m scripts.make_backtest_fixture --verify")


if __name__ == "__main__":
    main()
