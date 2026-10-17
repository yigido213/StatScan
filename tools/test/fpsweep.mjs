// Zararsiz dosyalar uzerinde yanlis alarm taramasi: node fpsweep.mjs <mod> <dosya|dizin>...
import fs from 'node:fs'; import path from 'node:path';
import { loadEngine, scan } from './engine.mjs';
const E = loadEngine(); const [mode, ...roots] = process.argv.slice(2);
const files = []; const walk = (p, d = 0) => { let st; try { st = fs.statSync(p); } catch { return; } if (st.isFile()) { if (st.size > 100 && st.size < 40e6) files.push(p); } else if (st.isDirectory() && d < 4) { let l = []; try { l = fs.readdirSync(p); } catch { } for (const x of l) walk(path.join(p, x), d + 1); } };
roots.forEach((r) => walk(r)); const lim = +(process.env.LIMIT || 400); const sel = files.slice(0, lim);
let n = 0; const dist = {};
for (const f of sel) { let b; try { b = fs.readFileSync(f); } catch { continue; } if (process.env.ELFONLY && !(b[0] === 0x7f && b[1] === 0x45)) continue; n++; let r; try { r = await scan(E, path.basename(f), b, mode); } catch (e) { console.log('HATA', f, e.message); continue; }
  const band = r.score >= 55 ? 'yuksek' : r.score >= 30 ? 'supheli' : r.score >= 10 ? 'dusuk' : 'temiz'; dist[band] = (dist[band] || 0) + 1;
  if (r.score >= 10) console.log(String(r.score).padStart(3), f, '\n     ', r.findings.filter((x) => x.w > 0).map((x) => x.id + '(' + x.w + ')').join(' ')); }
console.log('taranan', n, 'dagilim', JSON.stringify(dist));
