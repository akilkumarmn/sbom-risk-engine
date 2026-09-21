"""Formula behaviour, CVSS maths and ingestion edge cases."""
import json
from pathlib import Path

from engine import config
from engine.cvss import impact_subscore, parse_vector
from engine.sbom import correlate, parse_csv_scan, parse_cyclonedx, parse_nessus, parse_trivy
from engine.scoring import crit_multiplier, legacy_score, ml_score, soft_ceiling

FIX = config.ROOT / "tests" / "fixtures"


def test_cvss_impact_matches_nvd():
    for vec, exp in [("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 6.0),
                     ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 5.9),
                     ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 3.6),
                     ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 5.2),
                     ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 2.7)]:
        assert impact_subscore(parse_vector(vec)) == exp


def test_guide_formula_by_hand():
    f = {"p_model": 0.4, "epss": 0.5, "kev": True, "cvss_impact": 6.0, "fanin": 2, "max_fanin": 4,
         "scope_changed": True, "has_context": True,
         "services": [{"tier": 1, "internet_facing": True, "handles_pii": True}]}
    s = ml_score(f)
    L = 0.5 * 0.4 + 0.3 * 0.5 + 0.2 * 1
    I = (0.5 * 1.0 + 0.5 * 0.5) * 1.5 * 1.2
    assert abs(s["raw"] - 100 * L * I * 1.15) < 1e-9
    assert abs(s["risk"] - soft_ceiling(s["raw"])) < 1e-12


def test_asset_multiplier_rules():
    assert crit_multiplier({"has_context": False}) == 1.0
    assert crit_multiplier({"has_context": True, "services": []}) == 1.25  # unmatched -> tier 2
    assert crit_multiplier({"has_context": True, "services": [{"tier": 3}, {"tier": 2, "internet_facing": True}]}) == 1.5


def test_ablation_zeroes_one_signal():
    f = {"p_model": 0.9, "epss": 0.0, "kev": False, "cvss_impact": 3.0, "fanin": 0, "max_fanin": 0}
    assert ml_score(f, ("model",))["raw"] == 0.0
    assert ml_score(f)["raw"] > 0


def test_soft_ceiling_continuous_and_below_100():
    assert soft_ceiling(90.0) == 90.0
    assert 99.0 < soft_ceiling(150.0) < 100.0
    assert abs(soft_ceiling(90.0001) - 90.0001) < 1e-6


def test_legacy_formula_reproduces_cap1_log4shell():
    # Cap-1 sample: EPSS 0.975, KEV, impact 6.0, scope changed, 4 services (3 Critical + 1 High), fan-in 1
    services = [{"criticality": "Critical"}] * 3 + [{"criticality": "High"}]
    s = legacy_score({"epss": 0.975, "kev": True, "cvss_impact": 6.0, "scope_changed": True, "fanin": 1,
                      "services": services})
    assert s["likelihood"] == 0.9838 and s["blast_radius"] == 0.8 and s["impact"] == 0.9
    # 96.93 is what the Cap-1 dashboard's own scoreFindings() returns for this input
    assert s["risk"] == 96.93


def test_trivy_keeps_every_cve_per_package():
    doc = {"Results": [{"Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "a", "InstalledVersion": "1"},
        {"VulnerabilityID": "CVE-2", "PkgName": "a", "InstalledVersion": "1"}]}]}
    assert [f["cve_id"] for f in parse_trivy(doc)] == ["CVE-1", "CVE-2"]


def test_csv_quoted_commas():
    rows = parse_csv_scan((FIX / "scan_quoted.csv").read_text())
    assert len(rows) == 3
    assert rows[0]["description"] == "JNDI lookup, remote code execution" and rows[0]["host"] == "payment-api"
    assert rows[1]["description"] == 'Data binding, "Spring4Shell"' and rows[1]["vector_source"] == "none"


def test_nessus_multi_cve_and_skipped_no_cpe():
    f, skipped = parse_nessus((FIX / "scan.nessus").read_text())
    assert [x["cve_id"] for x in f] == ["CVE-2021-44228", "CVE-2021-45046"]
    assert all(x["host"] == "payment-api" and x["pkg_name"] == "log4j-core" for x in f)
    assert skipped == 1


def test_fanin_uses_bom_ref_for_purl_sboms():
    p = parse_cyclonedx(json.loads((config.ROOT / "backtest/fixtures/legacy-java-app/sbom.cdx.json").read_text()))
    from engine.sbom import fanin_map
    fm = fanin_map(p)
    assert fm["pkg:maven/ognl/ognl@3.0.6"] == 3  # xwork-core, struts2-core, root


def test_correlate_dedupes_component_cve_pairs():
    p = parse_cyclonedx({"components": [{"name": "a", "version": "1", "bom-ref": "r"}]})
    f = parse_trivy({"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "a", "InstalledVersion": "1"}]},
                                 {"Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "a", "InstalledVersion": "1"}]}]})
    m, u, _ = correlate(p, f)
    assert len(m) == 1 and not u


def test_api_service_matches_engine_ranking():
    from engine.service import Intel, score_documents
    fx = config.ROOT / "backtest/fixtures/acme"
    out = score_documents(Intel(), (fx / "sbom.cdx.json").read_text(), "trivy.json", (fx / "trivy.json").read_text(),
                          (fx / "asset-context.json").read_text())
    assert out["matched"] == 15 and [r["rank"] for r in out["ranked"]] == list(range(1, 16))
    assert out["intel"]["epss"].startswith("snapshot")
