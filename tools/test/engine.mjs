// StatScan motorunu HTML icinden cikarip Node'da yukler (test icin).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const here = path.dirname(fileURLToPath(import.meta.url));
export const HTML = path.resolve(here, '../../app/StatScan.html');
export function loadEngine(file = HTML) {
  const html = fs.readFileSync(file, 'utf8');
  const a = html.indexOf('<script>\n/* StatScan engine');
  if (a < 0) throw new Error('motor betigi bulunamadi');
  const b = html.indexOf('</script>', a);
  const code = html.slice(a + 8, b);
  const mod = { exports: {} };
  new Function('module', 'exports', code)(mod, mod.exports);
  return mod.exports;
}
export async function scan(E, name, data, mode = 'deep', extra = {}) {
  const u8 = data instanceof Uint8Array ? data : new Uint8Array(data);
  return E.scanFile({ name, size: u8.length, data: u8 }, Object.assign({ mode }, extra));
}
export const ids = (r) => r.findings.map((f) => f.id);
export function walk(r, fn, rel = '') { fn(r, rel); for (const c of r.children || []) walk(c, fn, rel + ' › ' + c.name); }
export function allIds(r) { const s = new Set(); walk(r, (x) => x.findings.forEach((f) => s.add(f.id))); return s; }
