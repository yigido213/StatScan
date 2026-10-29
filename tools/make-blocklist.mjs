#!/usr/bin/env node
// Kovan engelli listesi imzalayıcı (komut satırı). Uygulama içi "geliştirici modu" ile aynı biçimi üretir.
// Kullanım: node tools/make-blocklist.mjs <private.pem> [--add KV-XXXX-XXXX-XXXX-XXXX[:not]]... [--remove KV-...]... [--message "metin"] [--list]
// Mevcut blocklist.json (repo kökü) okunur, değişiklikler uygulanır, seq bir artırılır ve yeniden yazılır. Özel anahtar repoya KONMAZ.
import crypto from 'node:crypto'; import fs from 'node:fs'; import path from 'node:path'; import { createRequire } from 'node:module';
const require = createRequire(import.meta.url); const { blockModule: B } = require('../app/desktop/host.js');
const args = process.argv.slice(2); const keyPath = args.shift();
if (!keyPath || keyPath.startsWith('--')) { console.error('Kullanım: node tools/make-blocklist.mjs private.pem [--add KV-XXXX-XXXX-XXXX-XXXX[:not]] [--remove KV-...] [--message "metin"] [--list]'); process.exit(1); }
const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..'); const file = path.join(root, 'blocklist.json');
const priv = crypto.createPrivateKey(fs.readFileSync(keyPath)); const pub = crypto.createPublicKey(priv);
let cur = { seq: 0, blocked: [], message: '' }; if (fs.existsSync(file)) { try { cur = B.parseList(JSON.parse(fs.readFileSync(file, 'utf8')), pub); } catch (e) { console.error('Mevcut blocklist.json doğrulanamadı: ' + e.message); process.exit(1); } }
let entries = cur.blocked.slice(); let message = cur.message; let list = false;
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '--add') { const v = args[++i] || ''; const [id, ...n] = v.split(':'); const nid = B.normId(id); if (!nid) { console.error('Geçersiz kimlik: ' + id); process.exit(1); } entries = entries.filter((e) => e.id !== nid); entries.push({ id: nid, note: n.join(':') }); }
  else if (a === '--remove') { const nid = B.normId(args[++i]); if (!nid) { console.error('Geçersiz kimlik'); process.exit(1); } entries = entries.filter((e) => e.id !== nid); }
  else if (a === '--message') message = args[++i] || '';
  else if (a === '--list') list = true;
  else { console.error('Bilinmeyen seçenek: ' + a); process.exit(1); }
}
if (list) { console.log('seq ' + cur.seq + ', ' + cur.blocked.length + ' kimlik'); for (const e of cur.blocked) console.log(' ' + e.id + (e.note ? '  ' + e.note : '')); if (args.length === 1) process.exit(0); }
const w = B.signList(priv, pub, cur.seq + 1, entries, message); fs.writeFileSync(file, JSON.stringify(w, null, 2) + '\n');
console.log('blocklist.json yazıldı: seq ' + (cur.seq + 1) + ', ' + entries.length + ' kimlik. Commit edip main\'e push et; uygulamalar sonraki denetimde (en geç ~6 saat) alır.');
