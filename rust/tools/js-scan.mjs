// JS motoruyla kisa sonuc uretir (karsilastirma icin). Kullanim: node js-scan.mjs <mod> dosya...
import fs from 'node:fs';
import path from 'node:path';
import { loadEngine, scan } from '../../tools/test/engine.mjs';
const [mode, ...files] = process.argv.slice(2);
const E = loadEngine();
const out = [];
for (const p of files) {
  const r = await scan(E, path.basename(p), new Uint8Array(fs.readFileSync(p)), mode);
  out.push({ name: r.name, type: r.type, score: r.score, ownScore: r.ownScore, verdict: r.verdict, findings: r.findings.map((f) => ({ id: f.id, sev: f.sev, w: f.w })), children: r.children.length });
}
console.log(JSON.stringify(out));
