// Parity harness: node tests/node_score.js <sbom> <scan> <ctx|-> <intel.json> <fuzzy 0|1>
// Prints the scored findings as JSON (same pipeline as the dashboard).
const fs = require('fs');
const E = require('../site/engine.js');
const [sbomP, scanP, ctxP, intelP, fuzzy] = process.argv.slice(2);
const parsed = E.parseCycloneDX(JSON.parse(fs.readFileSync(sbomP, 'utf8')));
const text = fs.readFileSync(scanP, 'utf8');
const fmt = E.detectScanFormat(scanP, text);
const findings = fmt === 'trivy' ? E.parseTrivy(JSON.parse(text)) : E.parseCSVScan(text);
const corr = E.correlate(parsed, findings, fuzzy === '1');
const ctx = ctxP === '-' ? null : E.normalizeAssetContext(JSON.parse(fs.readFileSync(ctxP, 'utf8')));
const intel = JSON.parse(fs.readFileSync(intelP, 'utf8'));
const rows = E.scoreAll(E.enrichFindings(parsed, corr.matched, c => intel.cves[c] || null, ctx, intel.prior));
process.stdout.write(JSON.stringify({ fanin: E.faninMap(parsed), unmatched: corr.unmatched.length, log: corr.log, rows }));
