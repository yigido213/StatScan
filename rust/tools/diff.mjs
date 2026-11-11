// JS ve Rust motorlarini ayni dosyalarda karsilastirir. Kullanim: node diff.mjs <mod> dosya...
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const here = path.dirname(fileURLToPath(import.meta.url));
const [mode, ...files] = process.argv.slice(2);
const js = JSON.parse(execFileSync('node', [path.join(here, 'js-scan.mjs'), mode, ...files], { maxBuffer: 1 << 28 }).toString());
const rsBin = path.join(here, '../target/release/statscan');
let bad = 0;
const IGN = new Set(process.env.DIFF_IGNORE ? process.env.DIFF_IGNORE.split(',') : []);
files.forEach((f, i) => {
  let rs; try { rs = JSON.parse(execFileSync(rsBin, ['--mod', mode, '--ozet-json', f], { maxBuffer: 1 << 28 }).toString()); } catch (e) { rs = JSON.parse(e.stdout.toString()); }
  const J = js[i];
  const key = (x) => x.id + '|' + x.sev + '|' + x.w;
  const a = new Map(J.findings.filter((x) => !IGN.has(x.id)).map((x) => [x.id, key(x)])), b = new Map(rs.findings.filter((x) => !IGN.has(x.id)).map((x) => [x.id, key(x)]));
  const onlyJs = [...a].filter(([k, v]) => b.get(k) !== v).map(([, v]) => v);
  const onlyRs = [...b].filter(([k, v]) => a.get(k) !== v).map(([, v]) => v);
  const order = J.findings.filter((x) => !IGN.has(x.id) && b.has(x.id)).map((x) => x.id).join() === rs.findings.filter((x) => !IGN.has(x.id) && a.has(x.id)).map((x) => x.id).join();
  const ok = !onlyJs.length && !onlyRs.length && order && (IGN.size || (J.score === rs.score && J.verdict === rs.verdict));
  if (!ok) { bad++; console.log(`FARK ${path.basename(f)} [${mode}]: JS ${J.score}/${J.verdict} Rust ${rs.score}/${rs.verdict}\n   yalniz JS: ${onlyJs.join('; ') || '-'}\n   yalniz Rust: ${onlyRs.join('; ') || '-'}${order ? '' : '\n   SIRA farkli'}`); }
});
console.log(`${files.length - bad}/${files.length} dosya ayni (${mode})`);
process.exit(bad ? 1 : 0);
