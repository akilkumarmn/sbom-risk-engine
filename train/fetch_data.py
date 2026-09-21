"""Download every public source into data/raw/.

    python -m train.fetch_data                       # everything, 1999..current year
    python -m train.fetch_data --years 2019-2026     # training window only
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

from engine import config
from engine.sources import download, git_shallow_clone


def parse_years(spec: str) -> list[int]:
    a, _, b = spec.partition("-")
    return list(range(int(a), int(b or a) + 1))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--raw-dir", type=Path, default=config.RAW_DIR)
    ap.add_argument("--years", default=f"{config.FIRST_SCORE_YEAR}-{dt.date.today().year}")
    ap.add_argument("--freeze", default=config.FREEZE_DATE.isoformat(), help="EPSS snapshot date for the backtest")
    ap.add_argument("--skip-existing", action="store_true", help="reuse NVD year files already on disk")
    args = ap.parse_args(argv)
    raw: Path = args.raw_dir
    raw.mkdir(parents=True, exist_ok=True)
    manifest = {"fetched_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "files": {}}

    for y in parse_years(args.years):
        dest = raw / "nvd" / f"CVE-{y}.json.xz"
        if args.skip_existing and dest.exists():
            continue
        print(f"[nvd] {y}")
        try:
            download(config.NVD_URL.format(year=y), dest)
        except RuntimeError as e:
            if y >= dt.date.today().year:  # a brand-new year file may not exist yet
                print(f"  skipping {y}: {e}", file=sys.stderr)
                continue
            raise
    manifest["files"]["nvd"] = sorted(p.name for p in (raw / "nvd").glob("CVE-*.json.xz"))

    print("[kev]")
    try:
        download(config.KEV_URL, raw / "kev.json")
        manifest["files"]["kev"] = config.KEV_URL
    except RuntimeError:
        print("  cisa.gov unreachable, using the official GitHub mirror", file=sys.stderr)
        download(config.KEV_MIRROR_URL, raw / "kev.json")
        manifest["files"]["kev"] = config.KEV_MIRROR_URL

    print("[epss] current + freeze-date snapshot")
    download(config.EPSS_CURRENT_URL, raw / "epss_current.csv.gz")
    download(config.EPSS_DATED_URL.format(date=args.freeze), raw / f"epss_{args.freeze}.csv.gz")
    manifest["files"]["epss"] = ["epss_current.csv.gz", f"epss_{args.freeze}.csv.gz"]

    print("[poc] nomi-sec/PoC-in-GitHub (shallow clone)")
    git_shallow_clone(config.POC_GITHUB_REPO, raw / "poc-in-github")
    print("[poc] Exploit-DB files_exploits.csv")
    download(config.EXPLOITDB_CSV_URL, raw / "exploitdb.csv")

    (raw / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print("done ->", raw)


if __name__ == "__main__":
    main()
