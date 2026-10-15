#!/usr/bin/env node
// StatScan güncelleme paketi (.ssu) üretici ve imzalayıcı.
// Kullanım: node tools/make-ssu.mjs <sürüm> <özel-anahtar.pem> "<notlar>"
// Özel anahtar repoya KONMAZ; yalnızca imzalama sırasında okunur.
// Biçim: { manifest: "<JSON metni>", sig: base64(Ed25519(manifest UTF-8)), data: { yol: base64(gzip(içerik)) } }
import crypto from 'node:crypto'; import fs from 'node:fs'; import path from 'node:path'; import zlib from 'node:zlib';
const [, , version, keyPath, notes = ''] = process.argv;
if (!/^\d+\.\d+\.\d+$/.test(version || '') || !keyPath) { console.error('Kullanım: node tools/make-ssu.mjs 3.5.0 private.pem "notlar"'); process.exit(1); }
const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..'); const app = path.join(root, 'app');
const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]));
const rels = walk(app).map((f) => path.relative(app, f).split(path.sep).join('/')).sort((a, b) => (a === 'StatScan.html' ? -1 : b === 'StatScan.html' ? 1 : a.localeCompare(b)));
const files = {}, data = {};
for (const r of rels) { const buf = fs.readFileSync(path.join(app, r)); files[r] = { sha256: crypto.createHash('sha256').update(buf).digest('hex'), size: buf.length }; data[r] = zlib.gzipSync(buf, { level: 9 }).toString('base64'); }
const manifest = JSON.stringify({ format: 1, version, notes, minLoader: 1, created: new Date().toISOString(), files });
const priv = crypto.createPrivateKey(fs.readFileSync(keyPath)); const pub = crypto.createPublicKey(priv);
const sigBuf = crypto.sign(null, Buffer.from(manifest, 'utf8'), priv);
if (!crypto.verify(null, Buffer.from(manifest, 'utf8'), pub, sigBuf)) throw new Error('İmza doğrulanamadı');
const out = JSON.stringify({ manifest, sig: sigBuf.toString('base64'), data });
const name = `StatScan-${version}.ssu`; fs.writeFileSync(path.join(root, name), out);
const latest = { version, url: name, sha256: crypto.createHash('sha256').update(out).digest('hex'), notes };
fs.writeFileSync(path.join(root, 'latest.json'), JSON.stringify(latest, null, 2) + '\n');
console.log(name, (out.length / 1024).toFixed(1) + ' KB', '\nsha256', latest.sha256, '\ndosya sayısı', rels.length);
