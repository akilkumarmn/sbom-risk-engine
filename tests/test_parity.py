"""Browser (site/engine.js under Node) and Python engine must produce
identical findings, fan-in, services, scores and ranks on the same inputs."""
import json
import math
import random
import subprocess
import tempfile
from pathlib import Path

from engine import config
from engine.enrich import enrich_findings
from engine.sbom import correlate, fanin_map, normalize_asset_context, parse_cyclonedx, parse_scan
from engine.scoring import score_all

ROOT = config.ROOT
FIX = ROOT / "backtest" / "fixtures"
CASES = [
    (FIX / "acme/sbom.cdx.json", FIX / "acme/trivy.json", FIX / "acme/asset-context.json", False),
    (FIX / "acme/sbom.cdx.json", FIX / "acme/trivy.json", None, False),
    (FIX / "legacy-java-app/sbom.cdx.json", FIX / "legacy-java-app/trivy.json", FIX / "legacy-java-app/asset-context.json", False),
    (FIX / "acme/sbom.cdx.json", ROOT / "tests/fixtures/scan_quoted.csv", FIX / "acme/asset-context.json", True),
]
KEYS = ("cve_id", "component_ref", "cvss_base", "cvss_impact", "scope_changed", "vector_source", "fanin",
        "max_fanin", "p_model", "p_source", "epss", "kev", "has_context")


def _intel(cves, seed):
    rnd = random.Random(seed)
    out = {}
    for c in cves:
        if rnd.random() < 0.15:
            continue  # unknown CVE -> prior path
        out[c] = {"p_model": round(rnd.random(), 5), "epss": round(rnd.random(), 5), "kev": rnd.random() < 0.3,
                  "poc_github": rnd.random() < 0.4, "poc_exploitdb": rnd.random() < 0.2,
                  "cvss_impact": rnd.choice([3.6, 5.9, 6.0, 2.7]), "scope_changed": rnd.random() < 0.2,
                  "cvss_base": rnd.choice([7.5, 9.8, 10.0, 5.3])}
    return {"prior": 0.0123, "cves": out}


def _python(sbom, scan, ctx_path, intel, fuzzy):
    parsed = parse_cyclonedx(json.loads(Path(sbom).read_text()))
    _, findings, _ = parse_scan(Path(scan).name, Path(scan).read_text())
    matched, unmatched, log = correlate(parsed, findings, fuzzy=fuzzy)
    ctx = normalize_asset_context(json.loads(Path(ctx_path).read_text())) if ctx_path else None
    rows = score_all(enrich_findings(parsed, matched, lambda c: intel["cves"].get(c), ctx, intel["prior"]))
    return {"fanin": fanin_map(parsed), "unmatched": len(unmatched), "log": log, "rows": rows}


def _same(a, b, path):
    if isinstance(a, float) or isinstance(b, float):
        assert isinstance(a, (int, float)) and isinstance(b, (int, float)), f"{path}: {a!r} vs {b!r}"
        assert math.isclose(a, b, rel_tol=0, abs_tol=1e-12), f"{path}: {a!r} vs {b!r}"
    else:
        assert a == b, f"{path}: {a!r} vs {b!r}"


def test_parity():
    for i, (sbom, scan, ctx, fuzzy) in enumerate(CASES):
        parsed = parse_cyclonedx(json.loads(Path(sbom).read_text()))
        _, findings, _ = parse_scan(Path(scan).name, Path(scan).read_text())
        intel = _intel(sorted({f["cve_id"] for f in findings}), seed=i)
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(intel, fh)
        js = json.loads(subprocess.run(
            ["node", str(ROOT / "tests/node_score.js"), str(sbom), str(scan), str(ctx) if ctx else "-", fh.name,
             "1" if fuzzy else "0"], check=True, capture_output=True, text=True).stdout)
        py = _python(sbom, scan, ctx, intel, fuzzy)
        assert py["fanin"] == js["fanin"], f"case {i}: fan-in differs"
        assert py["unmatched"] == js["unmatched"] and py["log"] == js["log"]
        assert len(py["rows"]) == len(js["rows"]) > 0
        for r_py, r_js in zip(py["rows"], js["rows"]):
            for k in KEYS:
                _same(r_py[k], r_js[k], f"case {i} {r_py['cve_id']} {k}")
            assert [s["name"] for s in r_py["services"]] == [s["name"] for s in r_js["services"]]
            for mode in ("cvss", "legacy", "ml"):
                for k, v in r_py[mode].items():
                    _same(v, r_js[mode][k], f"case {i} {r_py['cve_id']} {mode}.{k}")


def test_formula_constants_match():
    js = subprocess.run(["node", "-e", "process.stdout.write(JSON.stringify(require('./site/engine.js').FORMULA))"],
                        cwd=ROOT, check=True, capture_output=True, text=True).stdout
    assert json.loads(js) == json.loads(json.dumps(config.FORMULA))
