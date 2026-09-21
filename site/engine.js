/* SBOM Context Risk Engine -- browser + Node scoring core.
 * Mirrors engine/cvss.py, engine/sbom.py and engine/scoring.py exactly.
 * tests/test_parity.py runs this file under Node and the Python engine on
 * the same fixtures and fails on any difference. Do not edit one without
 * the other. No DOM access in this file. */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.RiskEngine = api;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const FORMULA = {
    ml: { w_model: 0.5, w_epss: 0.3, w_kev: 0.2, w_cvss_impact: 0.5, w_fanin: 0.5, cvss_impact_max: 6.0,
          scope_changed_mult: 1.15, tier_mult: { '1': 1.5, '2': 1.25, '3': 1.0 },
          internet_facing_mult: 1.2, handles_pii_mult: 1.0, default_tier: 2 },
    legacy: { w_epss: 0.65, w_maturity: 0.35, maturity: { none: 0.05, poc: 0.5, weaponized: 0.9, kev: 1.0 },
              w_cvss_impact: 0.5, w_blast: 0.5, cvss_impact_max: 6.0,
              criticality_weight: { Critical: 1.0, High: 0.7, Medium: 0.4, Low: 0.2 },
              tier_to_criticality: { '1': 'Critical', '2': 'High', '3': 'Medium' },
              business_divisor: 3.0, fanin_divisor: 5.0, business_share: 0.75,
              scope_changed_mult: 1.15, trust_boundary_mult: 1.08 },
    soft_ceiling_start: 90.0,
    tiers: { Critical: 75.0, High: 50.0, Medium: 25.0 },
  };

  /* ---------------- CVSS ---------------- */
  const METRIC_VALUES = { AV: ['N','A','L','P'], AC: ['L','H'], PR: ['N','L','H'], UI: ['N','R'],
                          S: ['U','C'], C: ['H','L','N'], I: ['H','L','N'], A: ['H','L','N'] };
  const CIA = { H: 0.56, L: 0.22, N: 0.0 };

  function parseVector(vector) {
    if (!vector || typeof vector !== 'string') return null;
    let parts = vector.trim().split('/');
    if (parts.length && parts[0].toUpperCase().startsWith('CVSS:')) {
      if (!parts[0].toUpperCase().startsWith('CVSS:3')) return null;
      parts = parts.slice(1);
    }
    const out = {};
    for (const p of parts) {
      const i = p.indexOf(':'); if (i < 0) continue;
      const k = p.slice(0, i).trim().toUpperCase(), v = p.slice(i + 1).trim().toUpperCase();
      if (METRIC_VALUES[k]) { if (!METRIC_VALUES[k].includes(v)) return null; out[k] = v; }
    }
    return Object.keys(out).length === Object.keys(METRIC_VALUES).length ? out : null;
  }
  function impactSubscore(m) {
    if (!m) return null;
    const iss = 1 - (1 - CIA[m.C]) * (1 - CIA[m.I]) * (1 - CIA[m.A]);
    let impact = m.S === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
    impact = Math.max(0, impact);
    return Math.floor((impact + 1e-9) * 10 + 0.5) / 10;
  }
  function estimateImpactFromBase(base) {
    if (base === null || base === undefined || Number.isNaN(base)) return 0.0;
    return Math.min(6.0, Math.floor(base * 0.6 * 100 + 0.5) / 100);
  }

  /* ---------------- CycloneDX ---------------- */
  function normPurl(p) { return p ? p.trim().split(/[?#]/)[0].toLowerCase() : null; }
  function* walk(items) {
    for (const c of items || []) { if (c && typeof c === 'object') { yield c; yield* walk(c.components); } }
  }
  function toInt(v, d) { const n = parseInt(v, 10); return Number.isNaN(n) ? d : n; }

  function parseCycloneDX(sbom) {
    if (!sbom || typeof sbom !== 'object' || !Array.isArray(sbom.components))
      throw new Error("SBOM has no 'components' array -- is this valid CycloneDX?");
    const components = [];
    for (const c of walk(sbom.components)) {
      if (!(c.name && c.version)) continue;
      const props = {};
      for (const p of c.properties || []) if (p && typeof p === 'object') props[p.name] = p.value;
      components.push({
        bom_ref: c['bom-ref'] || `${c.name}@${c.version}`, name: c.name, group: c.group || '',
        version: String(c.version), purl: c.purl || '',
        dependency_depth: toInt(props['dependency:depth'], 0),
        dependency_type: props['dependency:type'] || 'direct',
      });
    }
    const rootC = (sbom.metadata || {}).component || {};
    const forward = {};
    for (const d of sbom.dependencies || []) {
      if (!(d && d.ref)) continue;
      forward[d.ref] = forward[d.ref] || [];
      for (const x of d.dependsOn || []) if (!forward[d.ref].includes(x)) forward[d.ref].push(x);
    }
    const reverse = {};
    for (const [ref, children] of Object.entries(forward))
      for (const ch of children) { reverse[ch] = reverse[ch] || []; if (!reverse[ch].includes(ref)) reverse[ch].push(ref); }
    return { components, forward, reverse, root_ref: rootC['bom-ref'] || '', root_name: rootC.name || '' };
  }
  function ancestors(parsed, ref) {
    const seen = new Set(), stack = [...(parsed.reverse[ref] || [])];
    while (stack.length) {
      const n = stack.pop(); if (seen.has(n)) continue;
      seen.add(n); stack.push(...(parsed.reverse[n] || []));
    }
    return [...seen].sort();
  }
  function faninMap(parsed) {
    const refs = new Set([...Object.keys(parsed.forward), ...parsed.components.map(c => c.bom_ref)]);
    const out = {}; for (const r of refs) out[r] = ancestors(parsed, r).length; return out;
  }

  /* ---------------- Scanner input ---------------- */
  function finding(cve, name, version, base, vector, desc, o) {
    o = o || {};
    const parsed = parseVector(vector);
    let impact = o.impact, scope = o.scope;
    if (impact === undefined || impact === null) impact = parsed ? impactSubscore(parsed) : estimateImpactFromBase(base);
    if (scope === undefined || scope === null) scope = !!parsed && parsed.S === 'C';
    return {
      cve_id: String(cve).trim(), pkg_name: name, pkg_version: String(version),
      purl: o.purl || '', bom_ref: o.bom_ref || '', host: o.host || '',
      cvss_base: Number(base || 0), cvss_vector: parsed ? vector : '',
      cvss_impact: Number(impact), scope_changed: !!scope,
      vector_source: parsed ? 'scan' : 'none',
      description: String(desc || '').slice(0, 300),
    };
  }
  function parseTrivy(doc) {
    const out = [];
    for (const r of doc.Results || []) for (const v of r.Vulnerabilities || []) {
      if (!(v.PkgName && v.InstalledVersion && v.VulnerabilityID)) continue;
      let base = 0, vector = '';
      const cvss = v.CVSS || {};
      for (const src of ['nvd', 'redhat', 'ghsa']) {
        if (cvss[src] && cvss[src].V3Score) { base = cvss[src].V3Score; vector = cvss[src].V3Vector || ''; break; }
      }
      const ident = v.PkgIdentifier || {};
      out.push(finding(v.VulnerabilityID, v.PkgName, v.InstalledVersion, base, vector, v.Title || v.Description || '',
                       { purl: ident.PURL || '', bom_ref: ident.BOMRef || '' }));
    }
    return out;
  }
  // RFC-4180 CSV (quoted fields, escaped quotes, CRLF)
  function csvRows(text) {
    const rows = []; let row = [], field = '', q = false;
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (q) {
        if (ch === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else q = false; }
        else field += ch;
      } else if (ch === '"') q = true;
      else if (ch === ',') { row.push(field); field = ''; }
      else if (ch === '\n' || ch === '\r') {
        if (ch === '\r' && text[i + 1] === '\n') i++;
        row.push(field); rows.push(row); row = []; field = '';
      } else field += ch;
    }
    if (field !== '' || row.length) { row.push(field); rows.push(row); }
    return rows.filter(r => !(r.length === 1 && r[0] === ''));
  }
  function parseCSVScan(text) {
    const rows = csvRows(text.replace(/^\uFEFF/, ''));
    const header = (rows[0] || []).map(h => h.trim());
    const missing = ['component', 'version', 'cve_id', 'cvss_base'].filter(r => !header.includes(r));
    if (missing.length) throw new Error(`CSV missing required column(s): ${missing.join(', ')}`);
    const out = [];
    for (const cells of rows.slice(1)) {
      const r = {}; header.forEach((h, i) => { r[h] = (cells[i] || '').trim(); });
      if (!r.cve_id) continue;
      const base = parseFloat(r.cvss_base || '0') || 0;
      const iv = r.cvss_impact_subscore ? parseFloat(r.cvss_impact_subscore) : NaN;
      const impact = Number.isNaN(iv) ? null : iv;
      const scope = r.cvss_scope ? r.cvss_scope.toUpperCase() === 'CHANGED' : null;
      out.push(finding(r.cve_id, r.component, r.version, base, r.cvss_vector || '', r.description || '',
                       { purl: r.purl || '', host: r.host || '', impact, scope }));
    }
    return out;
  }
  function parseCPE(cpe) {
    if (!cpe) return [null, null];
    const parts = cpe.replace('cpe:/', 'cpe:2.2:').split(':');
    const product = parts.length > 4 && parts[4] ? parts[4] : null;
    const version = parts.length > 5 && !['', '*', '-'].includes(parts[5]) ? parts[5] : null;
    return [product, version];
  }
  function parseNessus(xmlText, DOMParserImpl) {
    const P = DOMParserImpl || (typeof DOMParser !== 'undefined' ? DOMParser : null);
    if (!P) throw new Error('No XML parser available');
    const doc = new P().parseFromString(xmlText, 'text/xml');
    if (doc.getElementsByTagName('parsererror').length) throw new Error('Malformed XML');
    const out = []; let skipped = 0;
    const text = (el) => (el && el.textContent ? el.textContent.trim() : '');
    const child = (item, tag) => { for (const c of item.childNodes || []) if (c.nodeName === tag) return c; return null; };
    const children = (item, tag) => { const r = []; for (const c of item.childNodes || []) if (c.nodeName === tag) r.push(c); return r; };
    for (const host of Array.from(doc.getElementsByTagName('ReportHost'))) {
      const hostName = host.getAttribute('name') || '';
      for (const item of Array.from(host.getElementsByTagName('ReportItem'))) {
        const cves = children(item, 'cve').map(text).filter(Boolean);
        if (!cves.length) continue;
        const [product, version] = parseCPE(text(child(item, 'cpe')));
        if (!product || !version) { skipped += cves.length; continue; }
        const baseEl = child(item, 'cvss3_base_score') || child(item, 'cvss_base_score');
        const base = baseEl && text(baseEl) ? parseFloat(text(baseEl)) : 0.0;
        const vector = text(child(item, 'cvss3_vector'));
        const syn = text(child(item, 'synopsis'));
        const desc = syn || item.getAttribute('pluginName') || '';
        for (const cve of cves) out.push(finding(cve, product, version, base, vector, desc, { host: hostName }));
      }
    }
    return { findings: out, skipped };
  }
  function detectScanFormat(filename, text) {
    const n = filename.toLowerCase();
    if (n.endsWith('.nessus') || n.endsWith('.xml')) return 'nessus';
    if (n.endsWith('.csv')) return 'csv';
    try { const j = JSON.parse(text); if (j && typeof j === 'object' && 'Results' in j) return 'trivy'; } catch (e) { /* not JSON */ }
    return null;
  }

  /* ---------------- Correlation ---------------- */
  function nameVariants(c) {
    const n = c.name.toLowerCase(), g = c.group.toLowerCase();
    return g ? [n, `${g}:${n}`, `${g}/${n}`] : [n];
  }
  function correlate(parsed, findings, fuzzy) {
    const comps = parsed.components;
    const byRef = {}, byPurl = {}, byKey = {};
    for (const c of comps) {
      if (!(c.bom_ref in byRef)) byRef[c.bom_ref] = c;
      if (c.purl) { const k = normPurl(c.purl); if (!(k in byPurl)) byPurl[k] = c; }
      for (const nv of nameVariants(c)) { const k = `${nv}@${c.version}`; if (!(k in byKey)) byKey[k] = c; }
    }
    // Python dict comprehension keeps the LAST duplicate for byRef/byPurl
    for (const c of comps) { byRef[c.bom_ref] = c; if (c.purl) byPurl[normPurl(c.purl)] = c; }
    const matched = [], unmatched = [], log = [], seen = new Set();
    for (const f of findings) {
      let comp = null, how = null;
      const key = `${f.pkg_name.toLowerCase()}@${f.pkg_version}`;
      if (f.bom_ref && byRef[f.bom_ref]) { comp = byRef[f.bom_ref]; how = 'bom-ref'; }
      else if (f.purl && byPurl[normPurl(f.purl)]) { comp = byPurl[normPurl(f.purl)]; how = 'purl'; }
      else if (byKey[key]) { comp = byKey[key]; how = 'name@version'; }
      else if (fuzzy) {
        const sn = f.pkg_name.toLowerCase();
        for (const c of comps) {
          if (c.version !== f.pkg_version) continue;
          const cn = c.name.toLowerCase();
          if (sn.includes(cn) || cn.includes(sn)) {
            comp = c; how = 'fuzzy';
            log.push(`Fuzzy match: '${f.pkg_name}@${f.pkg_version}' -> SBOM component '${c.name}@${c.version}'`);
            break;
          }
        }
      }
      if (!comp) { unmatched.push(f); continue; }
      const k2 = comp.bom_ref + '\u0000' + f.cve_id;
      if (seen.has(k2)) continue;
      seen.add(k2);
      matched.push(Object.assign({}, f, {
        component_ref: comp.bom_ref, component: comp.name, component_group: comp.group, version: comp.version,
        component_purl: comp.purl, dependency_depth: comp.dependency_depth, dependency_type: comp.dependency_type,
        match: how, finding_id: `${comp.bom_ref}|${f.cve_id}`,
      }));
    }
    return { matched, unmatched, log };
  }

  /* ---------------- Asset context ---------------- */
  const CRIT_TO_TIER = { Critical: 1, High: 2, Medium: 3, Low: 3 };
  function normalizeAssetContext(doc) {
    if (!doc) return null;
    const services = doc.services;
    let items = [];
    if (services && !Array.isArray(services) && typeof services === 'object')
      items = Object.entries(services).map(([k, v]) => Object.assign({ name: k }, v || {}));
    else if (Array.isArray(services)) items = services.filter(s => s && typeof s === 'object' && s.name).map(s => Object.assign({}, s));
    else throw new Error("asset context needs a 'services' object or list");
    return { services: items.map(s => {
      let crit = s.criticality, tier = s.tier;
      if (tier === undefined || tier === null) tier = CRIT_TO_TIER[crit] || FORMULA.ml.default_tier;
      tier = parseInt(tier, 10);
      if (![1, 2, 3].includes(tier)) throw new Error(`service '${s.name}': tier must be 1, 2 or 3`);
      if (!(crit in FORMULA.legacy.criticality_weight)) crit = FORMULA.legacy.tier_to_criticality[String(tier)];
      return { name: String(s.name), tier, criticality: crit, internet_facing: !!s.internet_facing,
               handles_pii: !!s.handles_pii,
               components: (s.components || []).map(x => String(x).toLowerCase()),
               hosts: (s.hosts || []).map(x => String(x).toLowerCase()) };
    }) };
  }
  function servicesFor(f, parsed, ctx) {
    if (!ctx) return [];
    const compByRef = {}; for (const c of parsed.components) compByRef[c.bom_ref] = c;
    const c = compByRef[f.component_ref] || {};
    const ids = new Set([f.component_ref.toLowerCase(), `${f.component.toLowerCase()}@${f.version}`, f.component.toLowerCase()]);
    if (c.purl) { ids.add(c.purl.toLowerCase()); ids.add(normPurl(c.purl)); }
    if (c.group) ids.add(`${c.group.toLowerCase()}:${f.component.toLowerCase()}@${f.version}`);
    const chain = new Set([f.component.toLowerCase()]);
    for (const ref of ancestors(parsed, f.component_ref)) {
      const a = compByRef[ref];
      chain.add((a ? a.name : ref).toLowerCase());
      if (ref === parsed.root_ref && parsed.root_name) chain.add(parsed.root_name.toLowerCase());
    }
    const host = (f.host || '').toLowerCase();
    return ctx.services.filter(s => {
      const sname = s.name.toLowerCase();
      // "name@version" entries match the component itself (Cap-1 behaviour); bare names
      // also match any ancestor, so a service can be declared by its top-level component.
      return s.components.some(x => ids.has(x) || (!x.includes('@') && chain.has(x))) ||
        chain.has(sname) || (host && (host === sname || s.hosts.includes(host)));
    });
  }

  /* ---------------- Enrichment (mirror of engine/enrich.py) ----------------
   * lookup(cve) -> {p_model, epss, kev, poc_github, poc_exploitdb, cvss_impact,
   *                 scope_changed, cvss_base} or null */
  function enrichFindings(parsed, matched, lookup, ctx, priorP) {
    const fanin = faninMap(parsed);
    const vals = Object.values(fanin);
    const maxFanin = vals.length ? Math.max(...vals) : 0;
    return matched.map(f => {
      const rec = lookup(f.cve_id) || {};
      const has = Object.keys(rec).length > 0;
      const g = Object.assign({}, f);
      g.epss = Number(rec.epss || 0);
      g.kev = !!rec.kev;
      g.poc_github = !!rec.poc_github;
      g.poc_exploitdb = !!rec.poc_exploitdb;
      const hasP = rec.p_model !== undefined && rec.p_model !== null;
      g.p_model = hasP ? Number(rec.p_model) : Number(priorP || 0);
      g.p_source = hasP ? 'model' : 'prior';
      g.intel_found = has;
      if (g.vector_source === 'none' && rec.cvss_impact !== undefined && rec.cvss_impact !== null) {
        g.cvss_impact = Number(rec.cvss_impact);
        g.scope_changed = !!rec.scope_changed;
        g.vector_source = 'nvd';
        if (!g.cvss_base && rec.cvss_base !== undefined && rec.cvss_base !== null) g.cvss_base = Number(rec.cvss_base);
      }
      g.fanin = fanin[f.component_ref] || 0;
      g.max_fanin = maxFanin;
      g.services = servicesFor(f, parsed, ctx);
      g.has_context = ctx !== null && ctx !== undefined;
      return g;
    });
  }

  /* ---------------- Scoring ---------------- */
  function jsround(x, d) { const f = Math.pow(10, d); return Math.floor(x * f + 0.5) / f; }
  function softCeiling(raw) {
    const start = FORMULA.soft_ceiling_start;
    if (raw <= start) return raw;
    const span = 100 - start;
    return 100 - span * Math.exp(-(raw - start) / span);
  }
  function tierFor(s) {
    const t = FORMULA.tiers;
    return s >= t.Critical ? 'Critical' : s >= t.High ? 'High' : s >= t.Medium ? 'Medium' : 'Low';
  }
  function cvssScore(f) { const s = jsround(Number(f.cvss_base || 0) * 10, 2); return { raw: s, risk: s, tier: tierFor(s) }; }
  function critMultiplier(f, drop) {
    drop = drop || [];
    if (drop.includes('asset') || !f.has_context) return 1.0;
    const services = f.services || [];
    if (!services.length) return FORMULA.ml.tier_mult[String(FORMULA.ml.default_tier)];
    let best = 0;
    for (const s of services) {
      let m = FORMULA.ml.tier_mult[String(s.tier)];
      if (s.internet_facing) m *= FORMULA.ml.internet_facing_mult;
      if (s.handles_pii) m *= FORMULA.ml.handles_pii_mult;
      best = Math.max(best, m);
    }
    return best;
  }
  function mlScore(f, drop) {
    drop = drop || [];
    const M = FORMULA.ml;
    const p = drop.includes('model') ? 0 : Number(f.p_model || 0);
    const e = drop.includes('epss') ? 0 : Number(f.epss || 0);
    const k = drop.includes('kev') ? 0 : (f.kev ? 1 : 0);
    const likelihood = M.w_model * p + M.w_epss * e + M.w_kev * k;
    const cvssTerm = Math.min(1, Number(f.cvss_impact || 0) / M.cvss_impact_max);
    const maxFanin = Number(f.max_fanin || 0);
    const faninTerm = (drop.includes('fanin') || maxFanin <= 0) ? 0 : Number(f.fanin || 0) / maxFanin;
    const crit = critMultiplier(f, drop);
    const impact = (M.w_cvss_impact * cvssTerm + M.w_fanin * faninTerm) * crit;
    const scope = drop.includes('scope') ? 1 : (f.scope_changed ? M.scope_changed_mult : 1);
    const raw = 100 * likelihood * impact * scope;
    const risk = softCeiling(raw);
    return { likelihood, cvss_term: cvssTerm, fanin_term: faninTerm, crit_mult: crit, impact, scope_mult: scope,
             raw, risk, tier: tierFor(risk) };
  }
  function maturityLabel(f) {
    if (f.kev) return 'kev';
    if (['none', 'poc', 'weaponized'].includes(f.maturity_override)) return f.maturity_override;
    if (f.poc_exploitdb) return 'weaponized';
    if (f.poc_github) return 'poc';
    return 'none';
  }
  function legacyScore(f) {
    const L = FORMULA.legacy;
    const services = f.services || [];
    const weighted = services.reduce((s, x) => s + (L.criticality_weight[x.criticality] || 0), 0);
    const business = Math.min(1, weighted / L.business_divisor);
    const fanin = Number(f.fanin || 0);
    const graph = Math.min(1, fanin / L.fanin_divisor);
    const blast = services.length ? jsround(L.business_share * business + (1 - L.business_share) * graph, 3) : jsround(graph, 3);
    const label = maturityLabel(f);
    const maturity = L.maturity[label];
    const likelihood = jsround(L.w_epss * Number(f.epss || 0) + L.w_maturity * maturity, 4);
    const cvssComp = Math.min(1, Number(f.cvss_impact || 0) / L.cvss_impact_max);
    const impact = jsround(L.w_cvss_impact * cvssComp + L.w_blast * blast, 4);
    const crosses = services.length >= 3 || fanin >= 3;
    const scope = f.scope_changed ? L.scope_changed_mult : (crosses ? L.trust_boundary_mult : 1.0);
    const raw = likelihood * impact * 100 * scope;
    const risk = jsround(softCeiling(raw), 2);
    return { likelihood, impact, blast_radius: blast, business_score: business, graph_score: graph,
             maturity_label: label, maturity, scope_mult: scope, crosses_trust_boundary: crosses,
             raw, risk, tier: tierFor(risk) };
  }
  function cmpStr(a, b) { return a < b ? -1 : a > b ? 1 : 0; }
  function scoreAll(findings) {
    const out = findings.map(f => Object.assign({}, f, { cvss: cvssScore(f), legacy: legacyScore(f), ml: mlScore(f) }));
    for (const mode of ['cvss', 'legacy', 'ml']) {
      const idx = out.map((_, i) => i);
      idx.sort((a, b) => (out[b][mode].raw - out[a][mode].raw) || (Number(out[b].cvss_base || 0) - Number(out[a].cvss_base || 0))
        || cmpStr(out[a].cve_id, out[b].cve_id) || cmpStr(out[a].component_ref || '', out[b].component_ref || ''));
      idx.forEach((i, r) => { out[i][mode].rank = r + 1; });
    }
    return out;
  }

  return { FORMULA, parseVector, impactSubscore, parseCycloneDX, ancestors, faninMap, parseTrivy, parseCSVScan,
           parseNessus, parseCPE, detectScanFormat, correlate, normalizeAssetContext, servicesFor, enrichFindings, normPurl,
           jsround, softCeiling, tierFor, cvssScore, critMultiplier, mlScore, legacyScore, maturityLabel, scoreAll, csvRows };
});
