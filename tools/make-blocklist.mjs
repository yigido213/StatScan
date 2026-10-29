#!/usr/bin/env node
// Kovan imzalı engelli listesi (blocklist.json) üretici. Özel anahtar repoya KONMAZ; yalnızca imzalarken okunur.
// Kullanım:
//   node tools/make-blocklist.mjs <private.pem> list
//   node tools/make-blocklist.mjs <private.pem> add ABCD-EFGH-IJKL-MNOP "not (isteğe bağlı)"
//   node tools/make-blocklist.mjs <private.pem> remove ABCD-EFGH-IJKL-MNOP
//   node tools/make-blocklist.mjs <private.pem> notice "Engellenenlere gösterilecek mesaj"
// Sonuç repo köküne blocklist.json olarak yazılır (seq her seferinde artar); sonra commit + push et.
// Kimlik: kullanıcı Kovan → Ayarlar → Hakkında → "Kurulum kimliği"ni sana iletir; kimlik hiçbir yere otomatik gönderilmez.
import fs from 'node:fs'; import path from 'node:path'; import crypto from 'node:crypto'; import { createRequire } from 'node:module';
const require = createRequire(import.meta.url); const { accessModule: A } = require('../app/desktop/host.js');
const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..'); const file = path.join(root, 'blocklist.json');
const [, , keyPath, cmd, arg, ...rest] = process.argv; if (!keyPath || !['list', 'add', 'remove', 'notice'].includes(cmd)) { console.error('Kullanım: node tools/make-blocklist.mjs <private.pem> list|add|remove|notice [ID|metin] [not]'); process.exit(1); }
const priv = crypto.createPrivateKey(fs.readFileSync(keyPath)); if (priv.asymmetricKeyType !== 'ed25519') { console.error('Ed25519 anahtarı gerekli.'); process.exit(1); } const pub = crypto.createPublicKey(priv);
let cur = { seq: 0, notice: '', entries: [] }; if (fs.existsSync(file)) { const v = A.verifyBlocklist(fs.readFileSync(file, 'utf8'), pub); if (!v.ok) { console.error('Mevcut blocklist.json bu anahtarla doğrulanamadı (' + v.why + '); üzerine yazılmadı.'); process.exit(1); } cur = v; }
if (cmd === 'list') { console.log('seq', cur.seq, '· kayıt', cur.entries.length, cur.notice ? '· mesaj: ' + cur.notice : ''); for (const e of cur.entries) console.log(A.fmtId(e.id), e.added || '', e.note || ''); process.exit(0); }
const entries = cur.entries.map((e) => ({ ...e })); let notice = cur.notice;
if (cmd === 'add') { const id = A.normId(arg); if (!A.ID_RE.test(id)) { console.error('Kimlik 16 karakter olmalı (A–Z, 2–7).'); process.exit(1); } if (entries.some((e) => e.id === id)) { console.error('Zaten listede.'); process.exit(1); } entries.push({ id, note: rest.join(' '), added: new Date().toISOString().slice(0, 10) }); }
else if (cmd === 'remove') { const id = A.normId(arg); const n = entries.length; const left = entries.filter((e) => e.id !== id); if (left.length === n) { console.error('Listede yok.'); process.exit(1); } entries.length = 0; entries.push(...left); }
else notice = String(arg || '');
const text = A.signBlocklist(priv, { seq: cur.seq + 1, entries, notice }); const chk = A.verifyBlocklist(text, pub); if (!chk.ok) { console.error('Üretilen liste doğrulanamadı: ' + chk.why); process.exit(1); }
fs.writeFileSync(file, text); console.log('blocklist.json yazıldı · seq', chk.seq, '· kayıt', chk.entries.length, '\nŞimdi: git add blocklist.json && git commit && git push');
