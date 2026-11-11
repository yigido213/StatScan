// JS motorundaki kural/veri tablolarini Rust icin JSON'a doker (elle yeniden yazim hatasini onler).
// Kullanim: node rust/tools/dump-data.mjs   (depo kokunden)
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../..');
const html = fs.readFileSync(path.join(root, 'app/StatScan.html'), 'utf8');
const a = html.indexOf('<script>\n/* StatScan engine');
const b = html.indexOf('</script>', a);
let code = html.slice(a + 8, b);
const inject = `module.exports.__INT = { FP, FP_CAT, QUICK_IDS, BENIGN_HOSTS: BENIGN_HOSTS.source, BENIGN_FLAGS: BENIGN_HOSTS.flags, NEVER_LED, OFFICE_RE: OFFICE_RE.source, EXE_EXT: [...EXE_EXT], TEXT_EXT: [...TEXT_EXT], DECOY_EXT: [...DECOY_EXT], ONE_MAGIC, FACT_IDS: [...FACT_IDS], HEUR_IDS: [...HEUR_IDS], TECH, MITRE, BASIS_LABEL, LED, SKIP_LABELS, REFS, SRC, MODES, AXES, CAT_AXIS, sevRank, IOC_PATS: Object.fromEntries(Object.entries(IOC_PATS).map(([k, r]) => [k, { src: r.source, flags: r.flags }])) };\n`;
code = code.replace('if (typeof module !== \'undefined\' && module.exports) module.exports = api;', 'if (typeof module !== \'undefined\' && module.exports) { module.exports = api; ' + inject + ' }');
const mod = { exports: {} };
new Function('module', 'exports', code)(mod, mod.exports);
const E = mod.exports, I = E.__INT;
if (!I) throw new Error('ic degiskenler disari alinamadi');
const out = path.join(root, 'rust/crates/statscan-core/data');
const w = (n, o) => fs.writeFileSync(path.join(out, n), JSON.stringify(o, null, 1) + '\n');
w('str_rules.json', E.STR_RULES.map((r) => ({ id: r.id, re: r.re.source, flags: r.re.flags, w: r.w, sev: r.sev, t: r.t, why: r.why, act: r.act, cat: r.cat || '', distinct: r.distinct || 0, min_count: r.minCount || 0, scope: r.scope || 'any' })));
const modes = {}; for (const [k, m] of Object.entries(I.MODES)) modes[k] = Object.assign({}, m, { ids: m.ids ? [...m.ids] : null });
w('modes.json', modes);
w('meta.json', { fp: I.FP, fp_cat: I.FP_CAT, benign_hosts: { src: I.BENIGN_HOSTS, flags: I.BENIGN_FLAGS }, never_led: I.NEVER_LED, office_re: I.OFFICE_RE, exe_ext: I.EXE_EXT, text_ext: I.TEXT_EXT, decoy_ext: I.DECOY_EXT, one_magic: I.ONE_MAGIC, fact_ids: I.FACT_IDS, heur_ids: I.HEUR_IDS, tech: I.TECH, mitre: I.MITRE, basis_label: I.BASIS_LABEL, led: I.LED, skip_labels: I.SKIP_LABELS, refs: I.REFS, src: I.SRC, axes: I.AXES, cat_axis: I.CAT_AXIS, sev_rank: I.sevRank, ioc_pats: I.IOC_PATS, detect: E.DETECT, version: E.version });
console.log('veri yazildi:', out);
