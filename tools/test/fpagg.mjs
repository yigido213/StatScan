import fs from 'node:fs'; import path from 'node:path';
import { loadEngine, scan } from './engine.mjs';
const E = loadEngine(); const [mode, ...roots] = process.argv.slice(2);
const files = []; const seen = new Set(); const walk = (p, d = 0) => { let st; try { st = fs.statSync(p); } catch { return; } const rp = fs.realpathSync(p); if (seen.has(rp)) return; seen.add(rp); if (st.isFile()) { if (st.size > 100 && st.size < 40e6) files.push(p); } else if (st.isDirectory() && d < 5) { let l = []; try { l = fs.readdirSync(p); } catch { } for (const x of l) walk(path.join(p, x), d + 1); } };
roots.forEach((r) => walk(r)); const lim = +(process.env.LIMIT || 400); const agg = {}; const ex = {}; let n = 0;
for (const f of files.slice(0, lim)) { let b; try { b = fs.readFileSync(f); } catch { continue; } const pre = process.env.MAGIC; if (pre && !(b.subarray(0, pre.length).toString('latin1') === pre)) continue; n++; let r; try { r = await scan(E, path.basename(f), b, mode); } catch { continue; }
  const walkr = (x) => { for (const fi of x.findings) if (fi.w > 0) { agg[fi.id] = (agg[fi.id] || 0) + 1; (ex[fi.id] = ex[fi.id] || []).length < 2 && ex[fi.id].push(path.basename(f)); } (x.children || []).forEach(walkr); }; walkr(r); }
console.log('taranan', n); for (const [k, v] of Object.entries(agg).sort((a, b) => b[1] - a[1])) console.log(String(v).padStart(5), k, ex[k].join(','));
