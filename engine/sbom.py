"""SBOM + scan ingestion and correlation. This module and site/engine.js
implement the same algorithm; tests/test_parity.py runs both on the same
fixtures and requires identical output.

Fixes relative to the Cap-1 dashboard:
  * a package can carry many CVEs (the old parser kept only the last one);
  * fan-in is looked up by bom-ref (real SBOMs use purl bom-refs, so the old
    name@version lookup silently returned 0);
  * scope and impact sub-score come from the CVSS vector when one exists;
  * Nessus items with several <cve> tags yield several findings, and the
    ReportHost name is kept so asset context can map hosts to services;
  * CSV is parsed with a real CSV reader (quoted commas no longer break rows).
"""
from __future__ import annotations

import csv
import io
import json
import re
import xml.etree.ElementTree as ET

from . import config
from .cvss import estimate_impact_from_base, impact_subscore, parse_vector, scope_changed


# ---------------------------------------------------------------------------
# CycloneDX
# ---------------------------------------------------------------------------
def norm_purl(purl: str | None) -> str | None:
    if not purl:
        return None
    return re.split(r"[?#]", purl.strip())[0].lower()


def parse_cyclonedx(sbom: dict) -> dict:
    if not isinstance(sbom, dict) or not isinstance(sbom.get("components"), list):
        raise ValueError("SBOM has no 'components' array -- is this valid CycloneDX?")
    comps = []
    for c in _walk_components(sbom["components"]):
        if not (c.get("name") and c.get("version")):
            continue
        props = {p.get("name"): p.get("value") for p in c.get("properties") or [] if isinstance(p, dict)}
        comps.append({
            "bom_ref": c.get("bom-ref") or f"{c['name']}@{c['version']}",
            "name": c["name"], "group": c.get("group") or "", "version": str(c["version"]),
            "purl": c.get("purl") or "",
            "dependency_depth": _to_int(props.get("dependency:depth"), 0),
            "dependency_type": props.get("dependency:type") or "direct",
        })
    root = ((sbom.get("metadata") or {}).get("component") or {})
    forward = {}
    for d in sbom.get("dependencies") or []:
        if isinstance(d, dict) and d.get("ref"):
            forward.setdefault(d["ref"], [])
            forward[d["ref"]].extend(x for x in d.get("dependsOn") or [] if x not in forward[d["ref"]])
    reverse: dict[str, list[str]] = {}
    for ref, children in forward.items():
        for ch in children:
            reverse.setdefault(ch, [])
            if ref not in reverse[ch]:
                reverse[ch].append(ref)
    return {
        "components": comps,
        "forward": forward,
        "reverse": reverse,
        "root_ref": root.get("bom-ref") or "",
        "root_name": root.get("name") or "",
    }


def _walk_components(items):
    for c in items or []:
        if isinstance(c, dict):
            yield c
            yield from _walk_components(c.get("components"))


def _to_int(v, default):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def ancestors(parsed: dict, ref: str) -> list[str]:
    """All components that (transitively) depend on `ref`, sorted."""
    seen, stack = set(), list(parsed["reverse"].get(ref, []))
    while stack:
        node = stack.pop()
        if node in seen:
            continue
        seen.add(node)
        stack.extend(parsed["reverse"].get(node, []))
    return sorted(seen)


def fanin_map(parsed: dict) -> dict[str, int]:
    refs = set(parsed["forward"]) | {c["bom_ref"] for c in parsed["components"]}
    return {r: len(ancestors(parsed, r)) for r in refs}


# ---------------------------------------------------------------------------
# Scanner output -> list of findings
# ---------------------------------------------------------------------------
def _finding(cve, name, version, base, vector, desc, purl="", bom_ref="", host="", impact=None, scope=None):
    parsed = parse_vector(vector)
    if impact is None:
        impact = impact_subscore(parsed) if parsed else estimate_impact_from_base(base)
    if scope is None:
        scope = scope_changed(parsed)
    return {
        "cve_id": cve.strip(), "pkg_name": name, "pkg_version": str(version),
        "purl": purl or "", "bom_ref": bom_ref or "", "host": host or "",
        "cvss_base": float(base or 0.0), "cvss_vector": vector if parsed else "",
        "cvss_impact": float(impact), "scope_changed": bool(scope),
        "vector_source": "scan" if parsed else "none",
        "description": (desc or "")[:300],
    }


def parse_trivy(doc: dict) -> list[dict]:
    out = []
    for result in doc.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            if not (v.get("PkgName") and v.get("InstalledVersion") and v.get("VulnerabilityID")):
                continue
            base, vector = 0.0, ""
            cvss = v.get("CVSS") or {}
            for src in ("nvd", "redhat", "ghsa"):
                if (cvss.get(src) or {}).get("V3Score"):
                    base = cvss[src]["V3Score"]
                    vector = cvss[src].get("V3Vector") or ""
                    break
            ident = v.get("PkgIdentifier") or {}
            out.append(_finding(v["VulnerabilityID"], v["PkgName"], v["InstalledVersion"], base, vector,
                                v.get("Title") or v.get("Description") or "",
                                purl=ident.get("PURL") or "", bom_ref=ident.get("BOMRef") or ""))
    return out


def parse_csv_scan(text: str) -> list[dict]:
    text = text.lstrip("\ufeff")
    header = [h.strip() for h in next(csv.reader(io.StringIO(text)), [])]
    rows = list(csv.DictReader(io.StringIO(text)))
    required = ["component", "version", "cve_id", "cvss_base"]
    missing = [r for r in required if r not in header]
    if missing:
        raise ValueError(f"CSV missing required column(s): {', '.join(missing)}")
    out = []
    for r in rows:
        r = {k.strip(): (v or "").strip() for k, v in r.items() if isinstance(k, str) and not isinstance(v, list)}
        if not r.get("cve_id"):
            continue
        base = _num(r.get("cvss_base"), 0.0)
        impact = _num(r["cvss_impact_subscore"], None) if r.get("cvss_impact_subscore") else None
        scope = (r["cvss_scope"].upper() == "CHANGED") if r.get("cvss_scope") else None
        out.append(_finding(r["cve_id"], r["component"], r["version"], base, r.get("cvss_vector", ""),
                            r.get("description", ""), purl=r.get("purl", ""), host=r.get("host", ""),
                            impact=impact, scope=scope))
    return out


def _num(v, default):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def parse_cpe(cpe: str):
    if not cpe:
        return None, None
    parts = cpe.replace("cpe:/", "cpe:2.2:").split(":")
    product = parts[4] if len(parts) > 4 and parts[4] else None
    version = parts[5] if len(parts) > 5 and parts[5] not in ("", "*", "-") else None
    return product, version


def parse_nessus(xml_text: str) -> tuple[list[dict], int]:
    root = ET.fromstring(xml_text)
    out, skipped = [], 0
    for host in root.iter("ReportHost"):
        host_name = host.get("name") or ""
        for item in host.iter("ReportItem"):
            cves = [e.text.strip() for e in item.findall("cve") if e.text and e.text.strip()]
            if not cves:
                continue
            cpe_el = item.find("cpe")
            product, version = parse_cpe(cpe_el.text.strip() if cpe_el is not None and cpe_el.text else "")
            if not product or not version:
                skipped += len(cves)
                continue
            base_el = item.find("cvss3_base_score")
            if base_el is None:
                base_el = item.find("cvss_base_score")
            base = float(base_el.text) if base_el is not None and base_el.text else 0.0
            vec_el = item.find("cvss3_vector")
            vector = vec_el.text.strip() if vec_el is not None and vec_el.text else ""
            syn = item.find("synopsis")
            desc = syn.text.strip() if syn is not None and syn.text and syn.text.strip() else item.get("pluginName") or ""
            for cve in cves:
                out.append(_finding(cve, product, version, base, vector, desc, host=host_name))
    return out, skipped


def parse_scan(filename: str, text: str) -> tuple[str, list[dict], int]:
    name = filename.lower()
    if name.endswith(".nessus") or name.endswith(".xml"):
        f, skipped = parse_nessus(text)
        return "nessus", f, skipped
    if name.endswith(".csv"):
        return "csv", parse_csv_scan(text), 0
    doc = json.loads(text)
    if isinstance(doc, dict) and "Results" in doc:
        return "trivy", parse_trivy(doc), 0
    raise ValueError("Unrecognised scan format (expected Trivy JSON, Nessus XML or CSV)")


# ---------------------------------------------------------------------------
# Correlation: scan findings -> SBOM components
# ---------------------------------------------------------------------------
def _name_variants(c: dict) -> list[str]:
    n = c["name"].lower()
    g = c["group"].lower()
    v = [n]
    if g:
        v += [f"{g}:{n}", f"{g}/{n}"]
    return v


def correlate(parsed: dict, findings: list[dict], fuzzy: bool = False) -> tuple[list[dict], list[dict], list[str]]:
    """Returns (matched, unmatched, log). Match priority: bom-ref, purl,
    exact (group:)name@version, then optional fuzzy name containment."""
    comps = parsed["components"]
    by_ref = {c["bom_ref"]: c for c in comps}
    by_purl = {norm_purl(c["purl"]): c for c in comps if c["purl"]}
    by_key = {}
    for c in comps:
        for nv in _name_variants(c):
            by_key.setdefault(f"{nv}@{c['version']}", c)
    matched, unmatched, log, seen = [], [], [], set()
    for f in findings:
        comp, how = None, None
        if f["bom_ref"] and f["bom_ref"] in by_ref:
            comp, how = by_ref[f["bom_ref"]], "bom-ref"
        elif f["purl"] and norm_purl(f["purl"]) in by_purl:
            comp, how = by_purl[norm_purl(f["purl"])], "purl"
        elif f"{f['pkg_name'].lower()}@{f['pkg_version']}" in by_key:
            comp, how = by_key[f"{f['pkg_name'].lower()}@{f['pkg_version']}"], "name@version"
        elif fuzzy:
            sn = f["pkg_name"].lower()
            for c in comps:
                if c["version"] != f["pkg_version"]:
                    continue
                cn = c["name"].lower()
                if cn in sn or sn in cn:
                    comp, how = c, "fuzzy"
                    log.append(f"Fuzzy match: '{f['pkg_name']}@{f['pkg_version']}' -> SBOM component '{c['name']}@{c['version']}'")
                    break
        if comp is None:
            unmatched.append(f)
            continue
        key = (comp["bom_ref"], f["cve_id"])
        if key in seen:
            continue
        seen.add(key)
        matched.append({**f, "component_ref": comp["bom_ref"], "component": comp["name"],
                        "component_group": comp["group"], "version": comp["version"],
                        "component_purl": comp["purl"], "dependency_depth": comp["dependency_depth"],
                        "dependency_type": comp["dependency_type"], "match": how,
                        "finding_id": f"{comp['bom_ref']}|{f['cve_id']}"})
    return matched, unmatched, log


# ---------------------------------------------------------------------------
# Asset context (business impact)
# ---------------------------------------------------------------------------
_CRIT_TO_TIER = {"Critical": 1, "High": 2, "Medium": 3, "Low": 3}


def normalize_asset_context(doc: dict | None) -> dict | None:
    """Accepts the guide's format {"services": {name: {tier, internet_facing,
    handles_pii, components?, hosts?}}} and the Cap-1 inventory format
    {"services": [{name, criticality, internet_facing, components}]}."""
    if not doc:
        return None
    services = doc.get("services")
    items = []
    if isinstance(services, dict):
        items = [{"name": k, **(v or {})} for k, v in services.items()]
    elif isinstance(services, list):
        items = [dict(s) for s in services if isinstance(s, dict) and s.get("name")]
    else:
        raise ValueError("asset context needs a 'services' object or list")
    legacy = config.FORMULA["legacy"]
    out = []
    for s in items:
        crit = s.get("criticality")
        tier = s.get("tier")
        if tier is None:
            tier = _CRIT_TO_TIER.get(crit, config.FORMULA["ml"]["default_tier"])
        tier = int(tier)
        if tier not in (1, 2, 3):
            raise ValueError(f"service '{s['name']}': tier must be 1, 2 or 3")
        if crit not in legacy["criticality_weight"]:
            crit = legacy["tier_to_criticality"][str(tier)]
        out.append({"name": str(s["name"]), "tier": tier, "criticality": crit,
                    "internet_facing": bool(s.get("internet_facing", False)),
                    "handles_pii": bool(s.get("handles_pii", False)),
                    "components": [str(x).lower() for x in s.get("components") or []],
                    "hosts": [str(x).lower() for x in s.get("hosts") or []]})
    return {"services": out}


def services_for(finding: dict, parsed: dict, ctx: dict | None) -> list[dict]:
    if not ctx:
        return []
    comp_by_ref = {c["bom_ref"]: c for c in parsed["components"]}
    c = comp_by_ref.get(finding["component_ref"], {})
    ids = {finding["component_ref"].lower(), f"{finding['component'].lower()}@{finding['version']}",
           finding["component"].lower()}
    if c.get("purl"):
        ids.add(c["purl"].lower())
        ids.add(norm_purl(c["purl"]))
    if c.get("group"):
        ids.add(f"{c['group'].lower()}:{finding['component'].lower()}@{finding['version']}")
    chain = {finding["component"].lower()}
    for ref in ancestors(parsed, finding["component_ref"]):
        a = comp_by_ref.get(ref)
        chain.add((a["name"] if a else ref).lower())
        if ref == parsed["root_ref"] and parsed["root_name"]:
            chain.add(parsed["root_name"].lower())
    host = finding.get("host", "").lower()
    hits = []
    for s in ctx["services"]:
        sname = s["name"].lower()
        # entries with "@version" match the component itself (Cap-1 behaviour);
        # bare names also match any ancestor, so a service can be declared by
        # its top-level component ("everything under struts2-showcase").
        bare = {x for x in s["components"] if "@" not in x}
        if ((ids & set(s["components"])) or (bare & chain) or sname in chain
                or (host and (host == sname or host in s["hosts"]))):
            hits.append(s)
    return hits
