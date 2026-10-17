// src/engine/*.js parcalarini app/StatScan.html motoruna (const api = { ... oncesine) yerlestirir.
// Her parca /*#region ad*/ ... /*#endregion ad*/ arasinda tutulur; yeniden calistirmak guvenlidir.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const htmlPath = path.join(root, 'app/StatScan.html');
let html = fs.readFileSync(htmlPath, 'utf8');
const dir = path.join(root, 'src/engine');
const files = fs.readdirSync(dir).filter((f) => f.endsWith('.js')).sort();
const ANCHOR = '/*#anchor-ext*/';
if (!html.includes(ANCHOR)) {
  const i = html.indexOf('const api = { SRC, REFS');
  if (i < 0) throw new Error('const api bulunamadi');
  html = html.slice(0, i) + ANCHOR + '\n' + html.slice(i);
}
// once eski bolgeleri sil
html = html.replace(/\/\*#region ([\w-]+)\*\/[\s\S]*?\/\*#endregion \1\*\/\n?/g, '');
let block = '';
for (const f of files) {
  const name = f.replace(/^\d+-/, '').replace(/\.js$/, '');
  const code = fs.readFileSync(path.join(dir, f), 'utf8').replace(/\s+$/, '');
  block += `/*#region ${name}*/\n${code}\n/*#endregion ${name}*/\n`;
}
html = html.replace(ANCHOR + '\n', () => ANCHOR + '\n' + block);
fs.writeFileSync(htmlPath, html);
console.log('inject ok:', files.join(', '), '| html', html.length);
