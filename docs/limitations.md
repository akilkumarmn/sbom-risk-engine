# Limitations

- **KEV is an incomplete, biased label.** It lists exploitation that CISA confirmed and that matters to US federal
  systems; many exploited CVEs are never added, and additions lag exploitation. A "negative" is "not (yet) in KEV".
- **Low prevalence.** Only ~1-2% of CVEs are in KEV, which bounds achievable precision; PR-AUC and precision@k are
  the honest metrics, not accuracy.
- **EPSS already encodes much of the signal.** EPSS is trained on real exploitation telemetry. The model without
  EPSS is the project's independent contribution; the with-EPSS numbers in Table 1 use the current EPSS file and
  are an optimistic upper bound. The backtest uses the EPSS file of the freeze date.
- **Label maturity.** Recent CVEs have had less time to be added to KEV, so the test year's positives are
  under-counted; days-since-publish is kept out of the production model for this reason.
- **CVSS in the backtest is today's NVD value**, not the value on the freeze date (re-scoring is rare).
- **SBOM depth and fan-in are not reachability.** Whether vulnerable code is actually called is not analysed.
- **Asset context is user-supplied**, not discovered; its multipliers (1.5/1.25/1.0, ×1.2) are hand-set.
- **Likelihood weights (0.5/0.3/0.2) are hand-set;** the ablation shows each signal's contribution but the weights
  are not learned end to end.
- **Scanner coverage.** Nessus findings without a CPE cannot be correlated and are skipped (counted in the log).
  Name mismatches need fuzzy matching, which can mis-match similarly named packages.
- **Backtest size.** A single SBOM yields few later-exploited CVEs; statistical claims should use the population case.
- **Fixture provenance.** `backtest/fixtures/legacy-java-app` is a hand-authored stand-in; regenerate it with
  `scripts/build_fixtures.sh` (syft + Trivy) before quoting SBOM-case numbers. The acme fixture is the Cap-1 sample,
  and several of its scanner CVSS scores differ from NVD (the backtest uses NVD).
- **Offline development.** The code was developed in an environment without network access; everything was
  exercised end to end on a synthetic fixture in the real file formats. Real numbers come from the first run
  against the public feeds.

## Future work
Call-graph reachability (e.g. for Java via static analysis), VEX ingestion to suppress not-affected findings,
learning the formula weights end to end on backtest outcomes, and relabelling with organisation-specific
incident data.
